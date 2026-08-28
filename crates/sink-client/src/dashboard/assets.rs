use std::sync::Arc;

use axum::http::HeaderValue;
use bytes::Bytes;

use super::{EmbeddedAsset, EmbeddedAssetSource};

include!(concat!(env!("OUT_DIR"), "/dashboard_assets.rs"));

/// The production Vite output embedded into the `sink` executable at compile time.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProductionAssets;

impl EmbeddedAssetSource for ProductionAssets {
    fn get(&self, path: &str) -> Option<EmbeddedAsset> {
        let index = PRODUCTION_ASSETS
            .binary_search_by_key(&path, |(asset_path, _, _)| *asset_path)
            .ok()?;
        let (_, content_type, body) = PRODUCTION_ASSETS[index];
        Some(EmbeddedAsset {
            body: Bytes::from_static(body),
            content_type: HeaderValue::from_static(content_type),
        })
    }
}

/// Return the one immutable production asset source used by dashboard lifecycles.
#[must_use]
pub fn production_assets() -> Arc<dyn EmbeddedAssetSource> {
    Arc::new(ProductionAssets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_assets_are_sorted_unique_nonempty_and_include_index() {
        assert!(!PRODUCTION_ASSETS.is_empty());
        assert!(
            PRODUCTION_ASSETS
                .windows(2)
                .all(|pair| pair[0].0 < pair[1].0)
        );
        assert!(
            PRODUCTION_ASSETS
                .iter()
                .all(|(_, _, body)| !body.is_empty())
        );

        let index = ProductionAssets
            .get("/index.html")
            .expect("build.rs validates the production index");
        assert_eq!(index.content_type(), "text/html; charset=utf-8");
        assert!(index.body().starts_with(b"<!doctype html>"));
    }

    #[test]
    fn generated_vite_assets_have_exact_mime_types() {
        let scripts = PRODUCTION_ASSETS
            .iter()
            .filter(|(path, _, _)| path.ends_with(".js"))
            .collect::<Vec<_>>();
        let styles = PRODUCTION_ASSETS
            .iter()
            .filter(|(path, _, _)| path.ends_with(".css"))
            .collect::<Vec<_>>();
        assert!(!scripts.is_empty(), "Vite emitted no JavaScript asset");
        assert!(!styles.is_empty(), "Vite emitted no CSS asset");
        assert!(scripts.iter().all(|(_, content_type, _)| {
            *content_type == "application/javascript; charset=utf-8"
        }));
        assert!(
            styles
                .iter()
                .all(|(_, content_type, _)| *content_type == "text/css; charset=utf-8")
        );
    }
}
