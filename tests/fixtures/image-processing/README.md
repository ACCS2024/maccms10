# Independent image fixtures

These small synthetic files were authored for this repository's image regression tests using Python Pillow 12.0.0. Runtime tests require PHP only; they neither regenerate the fixtures with the library under test nor download external images.

- `animation.gif`: 80×40, three solid red/green/blue frames, delays 70/130/250 ms, Netscape repetition count 4, disposal 2.
- `disposal.gif`: 12×8 transparent canvas. Four frames add a red 4×4 block at (0,0), green at (4,0), blue at (8,4), then yellow at (0,4). Source frame disposals are 1/2/3/1, delays 80/150/220/310 ms, infinite looping. Pillow's independently composed frames are asserted in PHP, including the frame after restore-to-previous.
- `no-loop.gif`: 20×10 red/green/blue frames, delays 290/570/0 ms, no loop extension. Re-encoding must preserve single playback and exact centiseconds.
- `static.webp`: lossless 40×20 red image. Tests exercise the Imagick WebP path even when GD lacks WebP support.

The PHP helper reads GIF block metadata independently and uses GD to decode each full composed output frame. GIF color comparisons allow a five-level per-channel quantization tolerance; alpha, frame order, dimensions, delay integers and loop metadata are checked separately.
