use std::time::Duration;

use thiserror::Error;

use super::{
    CertificateRecord, IssuanceReason, IssuanceRequest, OrderRecord, OrderState, Timestamp,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    initial_delay: Duration,
    maximum_delay: Duration,
    namespace_failure_threshold: u32,
    namespace_failure_cooldown: Duration,
}

impl RetryPolicy {
    pub fn new(
        initial_delay: Duration,
        maximum_delay: Duration,
        namespace_failure_threshold: u32,
        namespace_failure_cooldown: Duration,
    ) -> Result<Self, InvalidSafetyLimits> {
        if initial_delay.is_zero()
            || maximum_delay < initial_delay
            || namespace_failure_threshold == 0
            || namespace_failure_cooldown.is_zero()
        {
            return Err(InvalidSafetyLimits);
        }

        Ok(Self {
            initial_delay,
            maximum_delay,
            namespace_failure_threshold,
            namespace_failure_cooldown,
        })
    }

    pub const fn initial_delay(&self) -> Duration {
        self.initial_delay
    }

    pub const fn maximum_delay(&self) -> Duration {
        self.maximum_delay
    }

    pub const fn namespace_failure_threshold(&self) -> u32 {
        self.namespace_failure_threshold
    }

    pub const fn namespace_failure_cooldown(&self) -> Duration {
        self.namespace_failure_cooldown
    }

    pub fn delay_for_failure(&self, consecutive_failures: u32) -> Duration {
        let exponent = consecutive_failures.saturating_sub(1).min(63);
        let multiplier = 1_u64.checked_shl(exponent).unwrap_or(u64::MAX);
        let seconds = self
            .initial_delay
            .as_secs()
            .saturating_mul(multiplier)
            .min(self.maximum_delay.as_secs());
        Duration::from_secs(seconds)
    }

    pub fn schedule_retry(
        &self,
        order: &mut OrderRecord,
        message: String,
        now: Timestamp,
    ) -> Timestamp {
        order.consecutive_failures = order.consecutive_failures.saturating_add(1);
        let backoff_at = now.saturating_add(self.delay_for_failure(order.consecutive_failures));
        let cooldown_until = (order.request.target.is_namespace()
            && order.consecutive_failures >= self.namespace_failure_threshold)
            .then(|| now.saturating_add(self.namespace_failure_cooldown));
        let retry_at = cooldown_until.map_or(backoff_at, |cooldown| cooldown.max(backoff_at));

        order.state = OrderState::RetryScheduled { retry_at };
        order.cooldown_until = cooldown_until;
        order.last_error = Some(message);
        order.updated_at = now;
        retry_at
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_secs(60),
            maximum_delay: Duration::from_secs(60 * 60),
            namespace_failure_threshold: 3,
            namespace_failure_cooldown: Duration::from_secs(60 * 60),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafetyLimits {
    max_active_claims_per_user: u32,
    max_pending_orders_per_user: u32,
    max_concurrent_orders: usize,
    retry: RetryPolicy,
}

impl SafetyLimits {
    pub fn new(
        max_active_claims_per_user: u32,
        max_pending_orders_per_user: u32,
        max_concurrent_orders: usize,
        retry: RetryPolicy,
    ) -> Result<Self, InvalidSafetyLimits> {
        if max_concurrent_orders == 0 {
            return Err(InvalidSafetyLimits);
        }

        Ok(Self {
            max_active_claims_per_user,
            max_pending_orders_per_user,
            max_concurrent_orders,
            retry,
        })
    }

    pub const fn max_active_claims_per_user(&self) -> u32 {
        self.max_active_claims_per_user
    }

    pub const fn max_pending_orders_per_user(&self) -> u32 {
        self.max_pending_orders_per_user
    }

    pub const fn max_concurrent_orders(&self) -> usize {
        self.max_concurrent_orders
    }

    pub const fn retry(&self) -> &RetryPolicy {
        &self.retry
    }
}

impl Default for SafetyLimits {
    fn default() -> Self {
        Self {
            max_active_claims_per_user: 20,
            max_pending_orders_per_user: 1,
            max_concurrent_orders: 2,
            retry: RetryPolicy::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QuotaSnapshot {
    /// Active claims currently owned by this request's user.
    pub active_claims_for_user: u32,
    /// Pending orders for this user excluding the request target.
    pub other_pending_orders_for_user: u32,
    /// Provider calls currently executing across all targets.
    pub concurrent_orders: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitExceeded {
    ActiveClaimsPerUser,
    PendingOrdersPerUser,
    ConcurrentGlobalOrders,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OrderPlan {
    Start,
    ReuseValidCertificate,
    Deduplicated(OrderState),
    RetryNotDue { retry_at: Timestamp },
    PermanentlyFailed,
    Rejected(LimitExceeded),
    InvalidRequest,
}

#[derive(Clone, Debug)]
pub struct IssuancePolicy {
    limits: SafetyLimits,
}

impl IssuancePolicy {
    pub fn new(limits: SafetyLimits) -> Self {
        Self { limits }
    }

    pub const fn limits(&self) -> &SafetyLimits {
        &self.limits
    }

    pub fn plan(
        &self,
        request: &IssuanceRequest,
        quota: QuotaSnapshot,
        certificate: Option<&CertificateRecord>,
        order: Option<&OrderRecord>,
        now: Timestamp,
    ) -> OrderPlan {
        if !request.validates_ownership_shape() {
            return OrderPlan::InvalidRequest;
        }

        if request.reason == IssuanceReason::NamespaceClaim
            && quota.active_claims_for_user >= self.limits.max_active_claims_per_user
        {
            return OrderPlan::Rejected(LimitExceeded::ActiveClaimsPerUser);
        }

        if request.reason != IssuanceReason::Renewal
            && certificate
                .and_then(|certificate| certificate.reusable_material(now))
                .is_some()
        {
            return OrderPlan::ReuseValidCertificate;
        }

        if let Some(order) = order {
            match order.state {
                OrderState::Queued | OrderState::InProgress => {
                    return OrderPlan::Deduplicated(order.state.clone());
                }
                OrderState::RetryScheduled { retry_at } if retry_at > now => {
                    return OrderPlan::RetryNotDue { retry_at };
                }
                OrderState::Failed => return OrderPlan::PermanentlyFailed,
                OrderState::RetryScheduled { .. } | OrderState::Succeeded => {}
            }
        }

        if request.owner.user_id().is_some()
            && quota.other_pending_orders_for_user >= self.limits.max_pending_orders_per_user
        {
            return OrderPlan::Rejected(LimitExceeded::PendingOrdersPerUser);
        }

        if quota.concurrent_orders >= self.limits.max_concurrent_orders {
            return OrderPlan::Rejected(LimitExceeded::ConcurrentGlobalOrders);
        }

        OrderPlan::Start
    }
}

impl Default for IssuancePolicy {
    fn default() -> Self {
        Self::new(SafetyLimits::default())
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("certificate safety limits are invalid")]
pub struct InvalidSafetyLimits;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificates::{CertificateProviderKind, CertificateTarget, Hostname, OrderOwner};

    fn claim_request() -> IssuanceRequest {
        IssuanceRequest {
            target: CertificateTarget::namespace(
                Hostname::parse("cloud.example.test").expect("valid hostname"),
            ),
            provider: CertificateProviderKind::Cloudflare,
            owner: OrderOwner::User("user-1".to_owned()),
            reason: IssuanceReason::NamespaceClaim,
        }
    }

    #[test]
    fn defaults_match_the_accepted_safety_limits() {
        let limits = SafetyLimits::default();

        assert_eq!(limits.max_active_claims_per_user(), 20);
        assert_eq!(limits.max_pending_orders_per_user(), 1);
        assert_eq!(limits.max_concurrent_orders(), 2);
        assert_eq!(limits.retry().initial_delay(), Duration::from_secs(60));
        assert_eq!(limits.retry().maximum_delay(), Duration::from_secs(60 * 60));
    }

    #[test]
    fn policy_rejects_each_configured_limit() {
        let policy = IssuancePolicy::default();
        let request = claim_request();
        let now = Timestamp::from_unix_seconds(1_000);

        assert_eq!(
            policy.plan(
                &request,
                QuotaSnapshot {
                    active_claims_for_user: 20,
                    ..QuotaSnapshot::default()
                },
                None,
                None,
                now,
            ),
            OrderPlan::Rejected(LimitExceeded::ActiveClaimsPerUser)
        );
        assert_eq!(
            policy.plan(
                &request,
                QuotaSnapshot {
                    other_pending_orders_for_user: 1,
                    ..QuotaSnapshot::default()
                },
                None,
                None,
                now,
            ),
            OrderPlan::Rejected(LimitExceeded::PendingOrdersPerUser)
        );
        assert_eq!(
            policy.plan(
                &request,
                QuotaSnapshot {
                    concurrent_orders: 2,
                    ..QuotaSnapshot::default()
                },
                None,
                None,
                now,
            ),
            OrderPlan::Rejected(LimitExceeded::ConcurrentGlobalOrders)
        );
    }

    #[test]
    fn exponential_backoff_caps_and_namespace_failures_enter_cooldown() {
        let retry = RetryPolicy::default();
        let now = Timestamp::from_unix_seconds(10_000);
        let mut order = OrderRecord::queued(claim_request(), now);

        let first = retry.schedule_retry(&mut order, "first".to_owned(), now);
        assert_eq!(first.unix_seconds(), 10_060);
        assert_eq!(order.cooldown_until, None);

        let second = retry.schedule_retry(&mut order, "second".to_owned(), now);
        assert_eq!(second.unix_seconds(), 10_120);
        assert_eq!(order.cooldown_until, None);

        let third = retry.schedule_retry(&mut order, "third".to_owned(), now);
        assert_eq!(third.unix_seconds(), 13_600);
        assert_eq!(order.cooldown_until, Some(third));

        order.consecutive_failures = 100;
        let capped = retry.schedule_retry(&mut order, "again".to_owned(), now);
        assert_eq!(capped.unix_seconds(), 13_600);
    }

    #[test]
    fn duplicate_orders_are_reused_until_a_scheduled_retry_is_due() {
        let policy = IssuancePolicy::default();
        let request = claim_request();
        let now = Timestamp::from_unix_seconds(1_000);
        let mut order = OrderRecord::queued(request.clone(), now);

        assert_eq!(
            policy.plan(&request, QuotaSnapshot::default(), None, Some(&order), now,),
            OrderPlan::Deduplicated(OrderState::Queued)
        );

        order.state = OrderState::RetryScheduled {
            retry_at: Timestamp::from_unix_seconds(1_060),
        };
        assert_eq!(
            policy.plan(&request, QuotaSnapshot::default(), None, Some(&order), now,),
            OrderPlan::RetryNotDue {
                retry_at: Timestamp::from_unix_seconds(1_060)
            }
        );
        assert_eq!(
            policy.plan(
                &request,
                QuotaSnapshot::default(),
                None,
                Some(&order),
                Timestamp::from_unix_seconds(1_060),
            ),
            OrderPlan::Start
        );
    }
}
