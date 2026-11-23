#!/usr/bin/env bash
# Скачать и собрать пиннованный NSS (+NSPR) для bangboo-net.
#
# Результат:
#   $NSS_DEPS/nss-3.134/nss       -> NSS_DIR
#   $NSS_DEPS/nss-3.134/dist/...  -> заголовки и библиотеки
#
# Зависимости: build-essential, ninja|ninja-build, python3, pip (gyp-next),
#              clang+libclang (для bindgen на этапе cargo).
set -euo pipefail

NSS_DEPS="${NSS_DEPS:-$HOME/bangboo-net-deps}"
NSS_VERSION="3.134"
NSPR_VERSION="4.41"
TARBALL="nss-${NSS_VERSION}-with-nspr-${NSPR_VERSION}.tar.gz"
URL="https://ftp.mozilla.org/pub/security/nss/releases/NSS_${NSS_VERSION//./_}_RTM/src/${TARBALL}"
SHA256="d37c4871ec83d72f5b98450458d09eb57e068a0b148a7f7cf5f6fa928af9664f"

mkdir -p "$NSS_DEPS"
cd "$NSS_DEPS"

if [ ! -d "nss-${NSS_VERSION}/dist/Release/lib" ]; then
    if [ ! -f "$TARBALL" ]; then
        echo ">> Скачиваю ${URL}"
        curl -fSL --retry 3 -o "$TARBALL" "$URL"
    fi
    echo ">> Проверяю sha256"
    echo "${SHA256}  ${TARBALL}" | sha256sum -c -

    echo ">> Распаковываю"
    tar xf "$TARBALL"

    echo ">> Собираю NSS (opt + static)"
    # gyp нужен в PATH (pip3 install --user gyp-next)
    export PATH="$HOME/.local/bin:$PATH"
    command -v gyp >/dev/null || {
        echo "!! gyp не найден. Установите: pip3 install --user gyp-next" >&2
        exit 1
    }
    (cd "nss-${NSS_VERSION}/nss" && ./build.sh \
        -Ddisable_tests=1 -Ddisable_dbm=1 -Ddisable_libpkix=1 \
        -Ddisable_ckbi=1 -Ddisable_fips=1 --opt --static)
fi

echo ">> NSS готов: ${NSS_DEPS}/nss-${NSS_VERSION}/nss"
echo "   Используйте: NSS_DIR=${NSS_DEPS}/nss-${NSS_VERSION}/nss NSS_PREBUILT=1"
