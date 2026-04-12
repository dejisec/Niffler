use anyhow::Result;
use rusqlite::params;

use super::Database;

impl Database {
    pub async fn toggle_star(&self, finding_id: i64) -> Result<bool> {
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO annotations (finding_id, starred)
                     VALUES (?1, 1)
                     ON CONFLICT(finding_id) DO UPDATE SET starred = 1 - starred",
                    params![finding_id],
                )?;
                let new_state: bool = conn.query_row(
                    "SELECT starred FROM annotations WHERE finding_id = ?1",
                    params![finding_id],
                    |row| row.get(0),
                )?;
                Ok::<_, rusqlite::Error>(new_state)
            })
            .await
            .map_err(Into::into)
    }

    pub async fn toggle_review(&self, finding_id: i64) -> Result<bool> {
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO annotations (finding_id, reviewed)
                     VALUES (?1, 1)
                     ON CONFLICT(finding_id) DO UPDATE SET reviewed = 1 - reviewed",
                    params![finding_id],
                )?;
                let new_state: bool = conn.query_row(
                    "SELECT reviewed FROM annotations WHERE finding_id = ?1",
                    params![finding_id],
                    |row| row.get(0),
                )?;
                Ok::<_, rusqlite::Error>(new_state)
            })
            .await
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use crate::classifier::Triage;
    use crate::web::db::test_helpers::{make_test_result, seed_test_data};
    use crate::web::db::{Database, FindingsQuery, ShowFilter};

    #[tokio::test]
    async fn test_star_finding() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = db.create_scan(&["10.0.0.1".into()], "scan").await.unwrap();
        let msg = make_test_result("10.0.0.1", "/exports", "/file.txt", Triage::Red, "Rule");
        db.insert_finding(scan_id, &msg).await.unwrap();

        let all = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                ..Default::default()
            })
            .await
            .unwrap();
        let id = all[0].id;

        let starred = db.toggle_star(id).await.unwrap();
        assert!(starred, "first toggle should star");

        let f = db.finding_by_id(id).await.unwrap().unwrap();
        assert!(f.starred);
    }

    #[tokio::test]
    async fn test_unstar_finding() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = db.create_scan(&["10.0.0.1".into()], "scan").await.unwrap();
        let msg = make_test_result("10.0.0.1", "/exports", "/file.txt", Triage::Red, "Rule");
        db.insert_finding(scan_id, &msg).await.unwrap();

        let all = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                ..Default::default()
            })
            .await
            .unwrap();
        let id = all[0].id;

        db.toggle_star(id).await.unwrap(); // star
        let unstarred = db.toggle_star(id).await.unwrap(); // unstar
        assert!(!unstarred, "second toggle should unstar");

        let f = db.finding_by_id(id).await.unwrap().unwrap();
        assert!(!f.starred);
    }

    #[tokio::test]
    async fn test_review_finding() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = db.create_scan(&["10.0.0.1".into()], "scan").await.unwrap();
        let msg = make_test_result("10.0.0.1", "/exports", "/file.txt", Triage::Red, "Rule");
        db.insert_finding(scan_id, &msg).await.unwrap();

        let all = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                ..Default::default()
            })
            .await
            .unwrap();
        let id = all[0].id;

        let reviewed = db.toggle_review(id).await.unwrap();
        assert!(reviewed, "first toggle should mark reviewed");

        let f = db.finding_by_id(id).await.unwrap().unwrap();
        assert!(f.reviewed);
    }

    #[tokio::test]
    async fn test_filter_starred() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        // Get first two finding IDs and star them
        let all = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                per_page: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        db.toggle_star(all[0].id).await.unwrap();
        db.toggle_star(all[1].id).await.unwrap();

        let starred = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                show: ShowFilter::Starred,
                per_page: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(starred.len(), 2, "should have exactly 2 starred findings");
    }

    #[tokio::test]
    async fn test_filter_unreviewed() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        // Review 3 findings
        let all = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                per_page: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        db.toggle_review(all[0].id).await.unwrap();
        db.toggle_review(all[1].id).await.unwrap();
        db.toggle_review(all[2].id).await.unwrap();

        let unreviewed = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                show: ShowFilter::Unreviewed,
                per_page: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(unreviewed.len(), 7, "10 total - 3 reviewed = 7 unreviewed");
    }
}
