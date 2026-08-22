#!/bin/sh
# Cold release builds of the three host configurations, separate target dirs.
S=/tmp/claude-1000/-home-bubu-sdwan/fe40b113-ed0e-4412-8c20-485019d29277/scratchpad/phase0-spike
cd $S/host || exit 1
mkdir -p $S/bin
for cfg in pulley cranelift cranelift,pulley; do
  name=$(echo $cfg | tr ',' '-')
  echo "=== config: $cfg (spike profile: lto=fat, cgu=1, panic=abort)"
  rm -rf $S/host/target-$name
  /usr/bin/env time -f "cold_build_wall_seconds[$cfg]=%e user=%U sys=%S maxrss_kib=%M" \
    cargo build --release --no-default-features --features "$cfg" --target-dir $S/host/target-$name 2>&1 | tail -3
  cp $S/host/target-$name/release/phase0-host $S/bin/host-$name
  cp $S/bin/host-$name $S/bin/host-$name.stripped
  strip $S/bin/host-$name.stripped
  ls -l $S/bin/host-$name $S/bin/host-$name.stripped
done
# Second pass: mimic the repo's [profile.release] (lto = "thin", codegen-units = 1, strip = true, panic = unwind)
for cfg in pulley cranelift cranelift,pulley; do
  name=$(echo $cfg | tr ',' '-')
  echo "=== config: $cfg (repo profile: lto=thin, cgu=1, panic=unwind, strip=true)"
  rm -rf $S/host/target-$name-repoprof
  CARGO_PROFILE_RELEASE_LTO=thin CARGO_PROFILE_RELEASE_PANIC=unwind CARGO_PROFILE_RELEASE_STRIP=true \
  /usr/bin/env time -f "cold_build_wall_seconds_repoprof[$cfg]=%e user=%U sys=%S maxrss_kib=%M" \
    cargo build --release --no-default-features --features "$cfg" --target-dir $S/host/target-$name-repoprof 2>&1 | tail -3
  cp $S/host/target-$name-repoprof/release/phase0-host $S/bin/host-$name-repoprof
  ls -l $S/bin/host-$name-repoprof
done
echo "=== baseline with repo profile"
cd $S/baseline-empty && rm -rf target-repoprof && CARGO_PROFILE_RELEASE_LTO=thin CARGO_PROFILE_RELEASE_PANIC=unwind CARGO_PROFILE_RELEASE_STRIP=true cargo build --release --target-dir target-repoprof 2>&1 | tail -1; ls -l target-repoprof/release/baseline-empty
echo ALLDONE
