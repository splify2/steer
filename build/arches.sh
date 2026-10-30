# Архитектуры OpenWrt, под которые собирается steer, и загрузчик musl каждой — общие для build.sh и
# внешних модулей (steer-box-connector собирает свой бинарник теми же целями и тем же загрузчиком:
# иначе модуль с чужой ABI встал бы рядом с libsteer и упал на первом вызове). Пояснения к списку и
# к загрузчику — в build.sh, у мест, где они используются.
#
# id:target:mcpu — пакетная архитектура OpenWrt, тройка zig и процессор.
ISAS="
mipsel_24kc:mipsel-linux-musl:mips32r2+soft_float
mips_24kc:mips-linux-musl:mips32r2+soft_float
aarch64_cortex-a53:aarch64-linux-musl:cortex_a53
aarch64_cortex-a72:aarch64-linux-musl:cortex_a72
aarch64_cortex-a73:aarch64-linux-musl:cortex_a73
aarch64_generic:aarch64-linux-musl:baseline
arm_cortex-a7_neon-vfpv4:arm-linux-musleabihf:cortex_a7
arm_cortex-a9:arm-linux-musleabi:cortex_a9
arm_cortex-a9_neon:arm-linux-musleabihf:cortex_a9+neon
arm_cortex-a9_vfpv3-d16:arm-linux-musleabihf:cortex_a9+vfp3d16
x86_64:x86_64-linux-musl:baseline
"

# Загрузчик musl по тройке цели: у динамического бинарника он вшит путём, и путь обязан совпасть с
# файлом на роутере (ld-musl-<арх>[hf|-sf].so.1).
interp_of() {  # ТРОЙКА MCPU
    case "$1" in
        mipsel-linux-musl*)     echo /lib/ld-musl-mipsel-sf.so.1 ;;
        mips-linux-musl*)       echo /lib/ld-musl-mips-sf.so.1 ;;
        aarch64-linux-musl*)    echo /lib/ld-musl-aarch64.so.1 ;;
        arm-linux-musleabihf*)  echo /lib/ld-musl-armhf.so.1 ;;
        arm-linux-musleabi*)    echo /lib/ld-musl-arm.so.1 ;;
        x86_64-linux-musl*)     echo /lib/ld-musl-x86_64.so.1 ;;
        *) echo "interp_of: неизвестная цель $1 ($2)" >&2; echo /lib/ld-musl-unknown.so.1 ;;
    esac
}
