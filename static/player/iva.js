// Keep the legacy IVA player key using the bundled DPlayer implementation.
(function () {
    var root = String(maccms.path || '').replace(/\/+$/, '');
    MacPlayer.Html = '<iframe src="' + root + '/static/player/dplayer.html" width="100%" height="100%" frameborder="0" scrolling="no" allowfullscreen></iframe>';
    MacPlayer.Show();
})();
