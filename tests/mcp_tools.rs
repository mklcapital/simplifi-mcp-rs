//! MCP tool-layer tests over the recorded-fixture mock transport.
//! Every tool runs credential-free: cargo test --features mock
#![cfg(feature = "mock")]

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use secrecy::SecretString;

use simplifi_mcp::mock::MockTransport;
use simplifi_mcp::server::{
    BulkImportInput, BulkUpdateTransactionsInput, CategorizeTransactionInput,
    CreateTransactionInput, ExportFormat, ExportTransactionsInput, GetTransactionInput,
    ListReferenceInput, ListTransactionsInput, RecurringDetectionInput, RefreshOnlyInput,
    SearchMerchantsInput, SearchReferenceInput, SearchTransactionsInput, SplitLineInput,
    SplitTransactionInput, SuggestCategoriesInput, TransactionPatchInput, UpdateTransactionInput,
};
use simplifi_mcp::transport::Transport;
use simplifi_mcp::{Config, Credentials, KeySource, LoginFlow, SimplifiClient, SimplifiMcpServer};

fn test_config(dir: &std::path::Path, allow_writes: bool, unverified: bool) -> Config {
    let mut c = Config::defaults();
    c.data_dir = dir.to_path_buf();
    c.key_source = KeySource::Static([7u8; 32]);
    c.client_secret = Some("test-client-secret".to_string());
    c.min_request_interval_ms = 0;
    c.page_limit = 2;
    c.mcp_allow_writes = allow_writes;
    c.enable_unverified_writes = unverified;
    c
}

async fn server_with(
    dir: &std::path::Path,
    allow_writes: bool,
    unverified: bool,
) -> SimplifiMcpServer {
    let cfg = test_config(dir, allow_writes, unverified);
    let client =
        SimplifiClient::with_transport(cfg, Transport::Mock(MockTransport::with_default_fixtures()))
            .expect("client");
    let creds = Credentials {
        username: "user@example.com".to_string(),
        password: SecretString::from("hunter2".to_string()),
    };
    match client.auth().login(&creds).await.expect("login") {
        LoginFlow::Complete => {}
        LoginFlow::MfaRequired(_) => panic!("unexpected MFA"),
    }
    SimplifiMcpServer::new(client)
}

async fn read_server(dir: &std::path::Path) -> SimplifiMcpServer {
    server_with(dir, false, false).await
}

async fn write_server(dir: &std::path::Path) -> SimplifiMcpServer {
    server_with(dir, true, true).await
}

/// Parse the JSON payload out of a tool result's first text content block.
fn payload(r: &CallToolResult) -> serde_json::Value {
    let v = serde_json::to_value(r).expect("serialize CallToolResult");
    let text = v["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no text content in {v}"));
    serde_json::from_str(text).expect("payload is JSON")
}

fn is_error(r: &CallToolResult) -> bool {
    serde_json::to_value(r).expect("serialize")["isError"]
        .as_bool()
        .unwrap_or(false)
}

// ------------------------------------------------------------------- router

#[test]
fn router_exposes_full_tool_inventory() {
    let router = SimplifiMcpServer::tool_router();
    let mut names: Vec<String> = router
        .list_all()
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    names.sort();
    let mut expected = vec![
        // upstream parity
        "list_transactions",
        "search_transactions",
        "get_transaction",
        "update_transaction",
        "categorize_transaction",
        "list_uncategorized_transactions",
        "search_merchants",
        "list_categories",
        "search_categories",
        "list_tags",
        "search_tags",
        "suggest_categories_for_merchant",
        // feature additions
        "create_transaction",
        "bulk_import_transactions",
        "split_transaction",
        "bulk_update_transactions",
        "list_accounts",
        "account_balances",
        "list_datasets",
        "export_transactions",
        "recurring_detection",
    ];
    expected.sort_unstable();
    assert_eq!(names, expected);
}

#[test]
fn schemas_are_strict_and_amounts_are_strings() {
    let router = SimplifiMcpServer::tool_router();
    let tool = router
        .list_all()
        .into_iter()
        .find(|t| t.name == "list_transactions")
        .expect("tool");
    let schema = serde_json::to_value(tool.input_schema.as_ref()).unwrap();
    assert_eq!(schema["additionalProperties"], serde_json::json!(false));
    // amounts cross the boundary as strings, not numbers (nullable: Option field)
    assert_eq!(
        schema["properties"]["minAmount"]["type"],
        serde_json::json!(["string", "null"])
    );
    assert_eq!(schema["properties"]["limit"]["maximum"], 200);
    assert_eq!(schema["properties"]["limit"]["minimum"], 1);
}

// ---------------------------------------------------------------- read lane

#[tokio::test]
async fn list_transactions_paginates_with_string_amounts() {
    let dir = tempfile::tempdir().unwrap();
    let s = read_server(dir.path()).await;
    let r = s
        .list_transactions(Parameters(ListTransactionsInput {
            limit: Some(2),
            ..Default::default()
        }))
        .await
        .unwrap();
    assert!(!is_error(&r));
    let p = payload(&r);
    assert_eq!(p["total"], 3);
    assert_eq!(p["items"].as_array().unwrap().len(), 2);
    assert_eq!(p["nextCursor"], "2");
    // postedOn desc: txn-3 first; amount is a decimal STRING
    assert_eq!(p["items"][0]["id"], "txn-3");
    assert_eq!(p["items"][0]["amount"], "1234.56");

    let r2 = s
        .list_transactions(Parameters(ListTransactionsInput {
            limit: Some(2),
            cursor: Some("2".to_string()),
            ..Default::default()
        }))
        .await
        .unwrap();
    let p2 = payload(&r2);
    assert_eq!(p2["items"].as_array().unwrap().len(), 1);
    assert!(p2.get("nextCursor").is_none());
    assert_eq!(p2["items"][0]["amount"], "-12.34");
}

#[tokio::test]
async fn list_transactions_filters() {
    let dir = tempfile::tempdir().unwrap();
    let s = read_server(dir.path()).await;
    // account filter
    let p = payload(
        &s.list_transactions(Parameters(ListTransactionsInput {
            account_id: Some("acc-2".to_string()),
            ..Default::default()
        }))
        .await
        .unwrap(),
    );
    assert_eq!(p["total"], 1);
    assert_eq!(p["items"][0]["id"], "txn-3");
    // amount range as strings
    let p = payload(
        &s.list_transactions(Parameters(ListTransactionsInput {
            min_amount: Some("-50.00".to_string()),
            max_amount: Some("-1.00".to_string()),
            ..Default::default()
        }))
        .await
        .unwrap(),
    );
    assert_eq!(p["total"], 2);
    // date range
    let p = payload(
        &s.list_transactions(Parameters(ListTransactionsInput {
            date_from: Some("2026-07-02".to_string()),
            date_to: Some("2026-07-02".to_string()),
            ..Default::default()
        }))
        .await
        .unwrap(),
    );
    assert_eq!(p["total"], 1);
    assert_eq!(p["items"][0]["id"], "txn-2");
    // invalid date rejected
    let r = s
        .list_transactions(Parameters(ListTransactionsInput {
            date_from: Some("07/02/2026".to_string()),
            ..Default::default()
        }))
        .await
        .unwrap();
    assert!(is_error(&r));
    assert_eq!(payload(&r)["error"], "invalid_argument");
}

#[tokio::test]
async fn search_get_uncategorized_and_merchants() {
    let dir = tempfile::tempdir().unwrap();
    let s = read_server(dir.path()).await;

    let p = payload(
        &s.search_transactions(Parameters(SearchTransactionsInput {
            query: "starbucks".to_string(),
            limit: None,
            cursor: None,
            account_id: None,
            date_from: None,
            date_to: None,
            min_amount: None,
            max_amount: None,
            include_deleted: None,
            refresh: None,
        }))
        .await
        .unwrap(),
    );
    assert_eq!(p["total"], 1);
    assert_eq!(p["items"][0]["id"], "txn-1");

    let p = payload(
        &s.get_transaction(Parameters(GetTransactionInput {
            transaction_id: "txn-2".to_string(),
            refresh_on_miss: None,
        }))
        .await
        .unwrap(),
    );
    assert_eq!(p["transaction"]["payee"], "SAFEWAY 0451");

    let r = s
        .get_transaction(Parameters(GetTransactionInput {
            transaction_id: "txn-nope".to_string(),
            refresh_on_miss: None,
        }))
        .await
        .unwrap();
    assert!(is_error(&r));
    assert_eq!(payload(&r)["error"], "not_found");

    let p = payload(
        &s.list_uncategorized_transactions(Parameters(ListTransactionsInput::default()))
            .await
            .unwrap(),
    );
    assert_eq!(p["total"], 1);
    assert_eq!(p["items"][0]["id"], "txn-2");

    let p = payload(
        &s.search_merchants(Parameters(SearchMerchantsInput {
            query: "star".to_string(),
            limit: None,
            include_deleted: None,
            refresh: None,
        }))
        .await
        .unwrap(),
    );
    assert_eq!(p["merchants"][0]["merchant"], "Starbucks");
    assert_eq!(p["merchants"][0]["count"], 1);
}

#[tokio::test]
async fn reference_tools() {
    let dir = tempfile::tempdir().unwrap();
    let s = read_server(dir.path()).await;

    let p = payload(
        &s.list_categories(Parameters(ListReferenceInput::default()))
            .await
            .unwrap(),
    );
    assert_eq!(p["categories"].as_array().unwrap().len(), 3);

    let p = payload(
        &s.search_categories(Parameters(SearchReferenceInput {
            query: "coffee".to_string(),
            refresh: None,
            limit: None,
        }))
        .await
        .unwrap(),
    );
    assert_eq!(p["categories"].as_array().unwrap().len(), 1);
    assert_eq!(p["categories"][0]["name"], "Coffee Shops");

    let p = payload(
        &s.list_tags(Parameters(ListReferenceInput::default()))
            .await
            .unwrap(),
    );
    assert_eq!(p["tags"].as_array().unwrap().len(), 2);

    let p = payload(
        &s.search_tags(Parameters(SearchReferenceInput {
            query: "vaca".to_string(),
            refresh: None,
            limit: None,
        }))
        .await
        .unwrap(),
    );
    assert_eq!(p["tags"][0]["name"], "vacation");

    let p = payload(
        &s.suggest_categories_for_merchant(Parameters(SuggestCategoriesInput {
            merchant: "starbucks".to_string(),
            limit: None,
            match_mode: None,
            refresh_categories: None,
        }))
        .await
        .unwrap(),
    );
    assert_eq!(p["suggestions"][0]["coa_id"], "cat-7");
    assert_eq!(p["suggestions"][0]["category_name"], "Coffee Shops");
}

#[tokio::test]
async fn accounts_balances_datasets() {
    let dir = tempfile::tempdir().unwrap();
    let s = read_server(dir.path()).await;

    let p = payload(
        &s.list_accounts(Parameters(RefreshOnlyInput::default()))
            .await
            .unwrap(),
    );
    assert_eq!(p["accounts"].as_array().unwrap().len(), 2);

    let p = payload(
        &s.account_balances(Parameters(RefreshOnlyInput::default()))
            .await
            .unwrap(),
    );
    assert_eq!(p["accounts"][0]["id"], "acc-1");
    assert_eq!(p["accounts"][0]["name"], "Checking");
    // balance surfaced as a decimal STRING
    assert_eq!(p["accounts"][0]["balances"]["currentBalance"], "1234.56");
    assert_eq!(p["accounts"][0]["type"], "BANK");

    let p = payload(&s.list_datasets().await.unwrap());
    assert_eq!(p["datasets"][0]["id"], "123456789012345678");
    assert_eq!(p["datasets"][0]["name"], "My Finances");
}

// --------------------------------------------------------------- write lane

#[tokio::test]
async fn writes_are_disabled_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let s = read_server(dir.path()).await;

    let r = s
        .update_transaction(Parameters(UpdateTransactionInput {
            transaction_id: "txn-1".to_string(),
            patch: TransactionPatchInput {
                memo: Some("nope".to_string()),
                ..Default::default()
            },
        }))
        .await
        .unwrap();
    assert!(is_error(&r));
    assert_eq!(payload(&r)["error"], "writes_disabled");

    let r = s
        .categorize_transaction(Parameters(CategorizeTransactionInput {
            transaction_id: "txn-1".to_string(),
            category_id: "cat-9".to_string(),
        }))
        .await
        .unwrap();
    assert_eq!(payload(&r)["error"], "writes_disabled");

    let r = s
        .create_transaction(Parameters(CreateTransactionInput {
            account_id: "acc-1".to_string(),
            posted_on: "2026-07-15".to_string(),
            payee: "X".to_string(),
            amount: "-1.00".to_string(),
            memo: None,
            category_id: None,
            tags: None,
            client_id: None,
        }))
        .await
        .unwrap();
    assert_eq!(payload(&r)["error"], "writes_disabled");

    // confirm:true is blocked read-only, but confirm:false preview still works.
    let r = s
        .bulk_import_transactions(Parameters(BulkImportInput {
            account_id: "acc-1".to_string(),
            csv: "7/4/2026,Coffee,-4.50".to_string(),
            confirm: Some(true),
        }))
        .await
        .unwrap();
    assert_eq!(payload(&r)["error"], "writes_disabled");

    let p = payload(
        &s.bulk_import_transactions(Parameters(BulkImportInput {
            account_id: "acc-1".to_string(),
            csv: "7/4/2026,Coffee,-4.50".to_string(),
            confirm: None,
        }))
        .await
        .unwrap(),
    );
    assert_eq!(p["preview"], true);
    assert_eq!(p["wouldCreate"], 1);
}

#[tokio::test]
async fn update_and_categorize_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let s = write_server(dir.path()).await;

    let r = s
        .update_transaction(Parameters(UpdateTransactionInput {
            transaction_id: "txn-1".to_string(),
            patch: TransactionPatchInput {
                memo: Some("patched via mcp".to_string()),
                amount: Some("-13.00".to_string()),
                ..Default::default()
            },
        }))
        .await
        .unwrap();
    assert!(!is_error(&r), "{:?}", payload(&r));
    let p = payload(&r);
    assert_eq!(p["mutation"]["status"], "SUCCESS");
    assert_eq!(p["transaction"]["memo"], "patched via mcp");
    assert_eq!(p["transaction"]["amount"], "-13.00");

    // write-through: the mirror sees the patched value immediately
    let p = payload(
        &s.get_transaction(Parameters(GetTransactionInput {
            transaction_id: "txn-1".to_string(),
            refresh_on_miss: Some(false),
        }))
        .await
        .unwrap(),
    );
    assert_eq!(p["transaction"]["memo"], "patched via mcp");

    let r = s
        .categorize_transaction(Parameters(CategorizeTransactionInput {
            transaction_id: "txn-1".to_string(),
            category_id: "cat-9".to_string(),
        }))
        .await
        .unwrap();
    let p = payload(&r);
    assert_eq!(p["transaction"]["coa"]["id"], "cat-9");
    assert_eq!(p["transaction"]["coa"]["type"], "CATEGORY");

    // empty patch is rejected before any wire traffic
    let r = s
        .update_transaction(Parameters(UpdateTransactionInput {
            transaction_id: "txn-1".to_string(),
            patch: TransactionPatchInput::default(),
        }))
        .await
        .unwrap();
    assert!(is_error(&r));
    assert_eq!(payload(&r)["error"], "invalid_argument");
}

fn split_lines(pairs: &[(&str, &str)]) -> Vec<SplitLineInput> {
    pairs
        .iter()
        .map(|(c, a)| SplitLineInput {
            category_id: c.to_string(),
            amount: a.to_string(),
            memo: None,
        })
        .collect()
}

#[tokio::test]
async fn split_transaction_roundtrip_and_gates() {
    let dir = tempfile::tempdir().unwrap();

    // read-only server: writes_disabled before anything else
    let s = read_server(dir.path()).await;
    let r = s
        .split_transaction(Parameters(SplitTransactionInput {
            transaction_id: "txn-1".to_string(),
            lines: split_lines(&[("cat-7", "-10.00"), ("cat-9", "-2.34")]),
        }))
        .await
        .unwrap();
    assert!(is_error(&r));
    assert_eq!(payload(&r)["error"], "writes_disabled");

    // writes on (unverified off): splits are live-verified, so no extra gate
    let s = server_with(dir.path(), true, false).await;
    let r = s
        .split_transaction(Parameters(SplitTransactionInput {
            transaction_id: "txn-1".to_string(),
            lines: split_lines(&[("cat-7", "-10.00"), ("cat-9", "-2.34")]),
        }))
        .await
        .unwrap();
    assert!(!is_error(&r), "{:?}", payload(&r));

    // fully enabled
    let s = write_server(dir.path()).await;
    // lines that don't total the amount (-12.34) are rejected pre-flight
    let r = s
        .split_transaction(Parameters(SplitTransactionInput {
            transaction_id: "txn-1".to_string(),
            lines: split_lines(&[("cat-7", "-10.00"), ("cat-9", "-2.00")]),
        }))
        .await
        .unwrap();
    assert!(is_error(&r));
    assert_eq!(payload(&r)["error"], "invalid_argument");

    let r = s
        .split_transaction(Parameters(SplitTransactionInput {
            transaction_id: "txn-1".to_string(),
            lines: split_lines(&[("cat-7", "-10.00"), ("cat-9", "-2.34")]),
        }))
        .await
        .unwrap();
    assert!(!is_error(&r), "{:?}", payload(&r));
    let p = payload(&r);
    assert_eq!(p["mutation"]["status"], "SUCCESS");
    // parsed splits ride along in the output, amounts as strings (display
    // scale follows the money module's f64 wire convention, so compare values)
    let splits = p["transaction"]["splits"].as_array().unwrap();
    assert_eq!(splits.len(), 2);
    assert_eq!(splits[0]["categoryId"], "cat-7");
    let amt = |v: &serde_json::Value| v.as_str().unwrap().parse::<f64>().unwrap();
    assert_eq!(amt(&splits[0]["amount"]), -10.00);
    assert_eq!(amt(&splits[1]["amount"]), -2.34);

    // write-through: the mirror shows the split immediately
    let p = payload(
        &s.get_transaction(Parameters(GetTransactionInput {
            transaction_id: "txn-1".to_string(),
            refresh_on_miss: Some(false),
        }))
        .await
        .unwrap(),
    );
    assert_eq!(p["transaction"]["splits"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn bulk_update_dry_run_then_confirm() {
    let dir = tempfile::tempdir().unwrap();
    let s = write_server(dir.path()).await;

    // dry run (default) matches without touching anything — works read-only too
    let r = s
        .bulk_update_transactions(Parameters(BulkUpdateTransactionsInput {
            query: Some("starbucks".to_string()),
            account_id: None,
            date_from: None,
            date_to: None,
            min_amount: None,
            max_amount: None,
            include_deleted: None,
            refresh: None,
            patch: TransactionPatchInput {
                is_reviewed: Some(true),
                ..Default::default()
            },
            confirm: None,
        }))
        .await
        .unwrap();
    assert!(!is_error(&r), "{:?}", payload(&r));
    let p = payload(&r);
    assert_eq!(p["preview"], true);
    assert_eq!(p["wouldUpdate"], 1);
    assert_eq!(p["sample"][0]["id"], "txn-1");

    // confirm applies the patch to every match
    let r = s
        .bulk_update_transactions(Parameters(BulkUpdateTransactionsInput {
            query: Some("starbucks".to_string()),
            account_id: None,
            date_from: None,
            date_to: None,
            min_amount: None,
            max_amount: None,
            include_deleted: None,
            refresh: None,
            patch: TransactionPatchInput {
                is_reviewed: Some(true),
                ..Default::default()
            },
            confirm: Some(true),
        }))
        .await
        .unwrap();
    assert!(!is_error(&r), "{:?}", payload(&r));
    let p = payload(&r);
    assert_eq!(p["preview"], false);
    assert_eq!(p["updated"], 1);
    assert_eq!(p["results"][0]["status"], "updated");

    let p = payload(
        &s.get_transaction(Parameters(GetTransactionInput {
            transaction_id: "txn-1".to_string(),
            refresh_on_miss: Some(false),
        }))
        .await
        .unwrap(),
    );
    assert_eq!(p["transaction"]["isReviewed"], true);
}

#[tokio::test]
async fn create_is_gated_until_unverified_writes_enabled() {
    let dir = tempfile::tempdir().unwrap();
    // writes allowed at MCP level, but the HAR-unverified endpoint stays off
    let s = server_with(dir.path(), true, false).await;
    let r = s
        .create_transaction(Parameters(CreateTransactionInput {
            account_id: "acc-1".to_string(),
            posted_on: "2026-07-15".to_string(),
            payee: "Backfill Coffee".to_string(),
            amount: "-4.50".to_string(),
            memo: None,
            category_id: None,
            tags: None,
            client_id: None,
        }))
        .await
        .unwrap();
    assert!(is_error(&r));
    assert_eq!(payload(&r)["error"], "unverified_endpoint_disabled");
}

#[tokio::test]
async fn create_and_bulk_import_when_fully_enabled() {
    let dir = tempfile::tempdir().unwrap();
    let s = write_server(dir.path()).await;

    let p = payload(
        &s.create_transaction(Parameters(CreateTransactionInput {
            account_id: "acc-1".to_string(),
            posted_on: "2026-07-15".to_string(),
            payee: "Backfill Coffee".to_string(),
            amount: "-4.50".to_string(),
            memo: Some("backfill".to_string()),
            category_id: Some("cat-7".to_string()),
            tags: None,
            client_id: None,
        }))
        .await
        .unwrap(),
    );
    assert_eq!(p["created"]["id"], "txn-new-9");

    let csv = "Date,Payee,Amount,Tags\n7/4/2026,Coffee Cart,-4.50,work\nbad-date,Broken,-1.00,\n7/6/2026,Bagels,-8.25,\n";
    let p = payload(
        &s.bulk_import_transactions(Parameters(BulkImportInput {
            account_id: "acc-1".to_string(),
            csv: csv.to_string(),
            confirm: Some(true),
        }))
        .await
        .unwrap(),
    );
    assert_eq!(p["preview"], false);
    assert_eq!(p["created"], 2);
    assert_eq!(p["attempted"], 2);
    assert_eq!(p["aborted"], false);
    assert_eq!(p["parseErrors"].as_array().unwrap().len(), 1);
    assert_eq!(p["results"][0]["status"], "created");
    assert_eq!(p["results"][0]["id"], "txn-new-9");
}

// ------------------------------------------------------------ analysis lane

#[tokio::test]
async fn export_json_and_csv() {
    let dir = tempfile::tempdir().unwrap();
    let s = read_server(dir.path()).await;

    let p = payload(
        &s.export_transactions(Parameters(ExportTransactionsInput {
            format: Some(ExportFormat::Json),
            ..Default::default()
        }))
        .await
        .unwrap(),
    );
    assert_eq!(p["format"], "json");
    assert_eq!(p["count"], 3);
    // oldest-first, amounts as strings
    assert_eq!(p["items"][0]["id"], "txn-1");
    assert_eq!(p["items"][0]["amount"], "-12.34");

    let p = payload(
        &s.export_transactions(Parameters(ExportTransactionsInput {
            format: Some(ExportFormat::Csv),
            ..Default::default()
        }))
        .await
        .unwrap(),
    );
    let csv = p["csv"].as_str().unwrap();
    assert!(csv.starts_with("Date,Payee,Amount,Tags"), "{csv}");
    assert!(csv.contains("7/1/2026,STARBUCKS #123,-12.34,"), "{csv}");

    let p = payload(
        &s.export_transactions(Parameters(ExportTransactionsInput {
            format: Some(ExportFormat::CsvFull),
            account_id: Some("acc-1".to_string()),
            ..Default::default()
        }))
        .await
        .unwrap(),
    );
    let csv = p["csv"].as_str().unwrap();
    assert!(csv.starts_with("Id,AccountId,PostedOn"), "{csv}");
    assert!(csv.contains("Coffee Shops"), "category name joined: {csv}");
    assert_eq!(p["count"], 2);
}

#[tokio::test]
async fn recurring_detection_runs_on_mirror() {
    let dir = tempfile::tempdir().unwrap();
    let s = read_server(dir.path()).await;
    let p = payload(
        &s.recurring_detection(Parameters(RecurringDetectionInput::default()))
            .await
            .unwrap(),
    );
    // three one-off fixture transactions -> nothing recurring
    assert_eq!(p["count"], 0);
    assert_eq!(p["groups"].as_array().unwrap().len(), 0);
}

// ------------------------------------------------------------------- SA-09

#[tokio::test]
async fn mutations_are_journaled_to_the_audit_log() {
    let dir = tempfile::tempdir().unwrap();
    let s = write_server(dir.path()).await;

    let r = s
        .update_transaction(Parameters(UpdateTransactionInput {
            transaction_id: "txn-1".to_string(),
            patch: TransactionPatchInput {
                memo: Some("audited".to_string()),
                ..Default::default()
            },
        }))
        .await
        .unwrap();
    assert!(!is_error(&r), "{:?}", payload(&r));

    let raw = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
    let recs: Vec<serde_json::Value> = raw
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(recs.len(), 2, "attempt + result: {raw}");
    assert_eq!(recs[0]["phase"], "attempt");
    assert_eq!(recs[0]["tool"], "update_transaction");
    assert_eq!(recs[0]["target"], "txn-1");
    // before-image captured BEFORE the mutation
    assert_eq!(recs[0]["before"]["id"], "txn-1");
    assert_ne!(recs[0]["before"]["memo"], "audited");
    assert_eq!(recs[1]["phase"], "result");
    assert_eq!(recs[1]["outcome"], "ok");
    assert_eq!(recs[1]["after"]["memo"], "audited");
    assert_eq!(recs[0]["opId"], recs[1]["opId"]);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.path().join("audit.jsonl"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "audit journal must be private");
    }

    // read-only servers never create a journal
    let dir2 = tempfile::tempdir().unwrap();
    let s2 = read_server(dir2.path()).await;
    let _ = s2
        .list_transactions(Parameters(ListTransactionsInput::default()))
        .await
        .unwrap();
    assert!(!dir2.path().join("audit.jsonl").exists());
}

#[tokio::test]
async fn write_quota_limits_mutations_per_hour() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = test_config(dir.path(), true, true);
    cfg.mcp_max_writes_per_hour = 2;
    let client =
        SimplifiClient::with_transport(cfg, Transport::Mock(MockTransport::with_default_fixtures()))
            .expect("client");
    let creds = Credentials {
        username: "user@example.com".to_string(),
        password: SecretString::from("hunter2".to_string()),
    };
    client.auth().login(&creds).await.expect("login");
    let s = SimplifiMcpServer::new(client);

    let update = |memo: &str| UpdateTransactionInput {
        transaction_id: "txn-1".to_string(),
        patch: TransactionPatchInput {
            memo: Some(memo.to_string()),
            ..Default::default()
        },
    };
    let r1 = s.update_transaction(Parameters(update("one"))).await.unwrap();
    assert!(!is_error(&r1), "{:?}", payload(&r1));
    let r2 = s.update_transaction(Parameters(update("two"))).await.unwrap();
    assert!(!is_error(&r2), "{:?}", payload(&r2));
    let r3 = s.update_transaction(Parameters(update("three"))).await.unwrap();
    assert!(is_error(&r3));
    assert_eq!(payload(&r3)["error"], "write_quota_exceeded");

    // bulk import counts one per row: 2 rows do not fit in the exhausted window either
    let r = s
        .bulk_import_transactions(Parameters(BulkImportInput {
            account_id: "acc-1".to_string(),
            csv: "7/4/2026,Coffee,-4.50\n7/5/2026,Tea,-3.25".to_string(),
            confirm: Some(true),
        }))
        .await
        .unwrap();
    assert!(is_error(&r));
    assert_eq!(payload(&r)["error"], "write_quota_exceeded");
}

// ------------------------------------------------------------------ SA-13

#[tokio::test]
async fn refresh_cannot_bypass_sync_floor() {
    let dir = tempfile::tempdir().unwrap();
    let s = read_server(dir.path()).await;
    // initial sync
    let first = s.store().ensure_transactions(false).await.unwrap();
    assert_eq!(first, simplifi_mcp::store::SyncOutcome::Synced);
    // forced refresh immediately after: floor (default 30s) suppresses upstream traffic
    let second = s.store().ensure_transactions(true).await.unwrap();
    assert_eq!(second, simplifi_mcp::store::SyncOutcome::CacheHit);
}
