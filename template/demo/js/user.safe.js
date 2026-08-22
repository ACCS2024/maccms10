(function (window, $) {
    'use strict';

    var MAC = window.MAC || {};

    MAC.CheckBox = {
        All: function (name) {
            $(document.getElementsByName(name)).prop('checked', true);
        },
        Other: function (name) {
            $(document.getElementsByName(name)).each(function () {
                this.checked = !this.checked;
            });
        },
        Count: function (name) {
            return $(document.getElementsByName(name)).filter(':checked').length;
        },
        Ids: function (name) {
            return $(document.getElementsByName(name)).filter(':checked').map(function () {
                return this.value;
            }).get().join(',');
        }
    };

    window.MAC = MAC;
}(window, jQuery));
