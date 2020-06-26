# ya-runtime-vm

## Prepare

### Image

```sh
docker pull alpine
cd poc
./gvmkit build alpine
mv out-*.golem-app alpine.golem-app
```

### Path to poc

```sh
ln -s ../../poc target/debug/
```

## Run

```sh
cargo run -- --task-package poc/alpine.golem-app --workdir . \
    run --entrypoint ls /
```
