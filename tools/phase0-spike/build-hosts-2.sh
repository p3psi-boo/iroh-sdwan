#!/bin/sh
# Remaining cold builds; target dirs on /home (tmpfs /tmp is only 2 GiB).
S=/tmp/claude-1000/-home-bubu-sdwan/fe40b113-ed0e-4412-8c20-485019d29277/scratchpad/phase0-spike
T=/home/bubu/.cache/ironet-phase0-spike
cd $S/host || exit 1
for cfg in cranelift,pulley; do
  name=$(echo $cfg | tr ',' '-')
  echo "=== config: $cfg (spike profile: lto=fat, cgu=1, panic=abort)"
  rm -rf $T/target-$name
  /usr/bin/env time -f "cold_build_wall_seconds[$cfg]=%e user=%U sys=%S maxrss_kib=%M" \
    cargo build --release --no-default-features --features "$cfg" --target-dir $T/target-$name 2>&1 | tail -3
  cp $T/target-$name/release/phase0-host $S/bin/host-$name
  cp $S/bin/host-$name $S/bin/host-$name.stripped
  strip $S/bin/host-$name.stripped
  ls -l $S/bin/host-$name $S/bin/host-$name.stripped
  rm -rf $T/target-$name
done
for cfg in pulley cranelift cranelift,pulley; do
  name=$(echo $cfg | tr ',' '-')
  echo "=== config: $cfg (repo profile: lto=thin, cgu=1, panic=unwind, strip=true)"
  rm -rf $T/target-$name-repoprof
  CARGO_PROFILE_RELEASE_LTO=thin CARGO_PROFILE_RELEASE_PANIC=unwind CARGO_PROFILE_RELEASE_STRIP=true \
  /usr/bin/env time -f "cold_build_wall_seconds_repoprof[$cfg]=%e user=%U sys=%S maxrss_kib=%M" \
    cargo build --release --no-default-features --features "$cfg" --target-dir $T/target-$name-repoprof 2>&1 | tail -3
  cp $T/target-$name-repoprof/release/phase0-host $S/bin/host-$name-repoprof
  ls -l $S/bin/host-$name-repoprof
  rm -rf $T/target-$name-repoprof
done
echo "=== baseline with repo profile"
cd $S/baseline-empty && CARGO_PROFILE_RELEASE_LTO=thin CARGO_PROFILE_RELEASE_PANIC=unwind CARGO_PROFILE_RELEASE_STRIP=true cargo build --release --target-dir $T/baseline-repoprof 2>&1 | tail -1; ls -l $T/baseline-repoprof/release/baseline-empty; cp $T/baseline-repoprof/release/baseline-empty $S/bin/baseline-empty-repoprof; rm -rf $T/baseline-repoprof
cp $S/baseline-empty/baseline-empty.stripped $S/bin/baseline-empty.stripped
echo ALLDONE
