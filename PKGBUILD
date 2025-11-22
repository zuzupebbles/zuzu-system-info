# Maintainer: Peter Knauer <zuzu@quantweave.ca>
pkgname=zuzu-system-info
pkgver=0.1.0
pkgrel=1
pkgdesc="Collects structured Linux system snapshots and generates LLM-friendly Markdown reports"
arch=('any')
url="https://github.com/zuzupebbles/zuzu-system-info"
license=('MIT')
depends=('python')
makedepends=()
source=("zuzu-system-info.py")
sha256sums=('SKIP')

package() {
  install -Dm755 "$srcdir/zuzu-system-info.py" \
    "$pkgdir/usr/local/sbin/zuzu-system-info"
}
