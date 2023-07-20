use ya_runtime_sdk::run;
use ya_runtime_vm::Runtime;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run::<Runtime>().await
}
