# Demo theme frontend dependencies

These files are pinned local copies of upstream release artifacts. Keep the
`integrity` attributes in the templates in sync whenever a file is updated.

| Dependency | Version | Upstream artifact | Local SHA-384 |
| --- | --- | --- | --- |
| jQuery | 3.7.1 | `https://code.jquery.com/jquery-3.7.1.min.js` | `d47db5ee0c125722d221f68bc476c4edd45bdefe2660229ba50bf3c7471e81e8eed4c56c1ab5f9c57c40becfc781e16c` |
| jQuery Lazy Load | 1.9.7 | `https://raw.githubusercontent.com/tuupola/jquery_lazyload/1.9.7/jquery.lazyload.min.js` | `0f7594be6e234e38bc202a8b8c5f47fbfdce663b8adbb1da3206e19a9ad8a9c3c68a748773822413892e1551ffe80b20` |

The Lazy Load file has one trailing newline added by the repository patch, so
its local hash intentionally differs from the raw upstream response.
