(function () {
  'use strict';
  const $ = id => document.getElementById(id);
  let toastTimer;
  function toast(message) {
    const element = $('toast');
    if (!element) return;
    clearTimeout(toastTimer); element.textContent = message; element.hidden = false;
    toastTimer = setTimeout(() => { element.hidden = true; }, 2400);
  }
  function fallbackCopy(text) {
    const active = document.activeElement;
    const field = document.createElement('textarea'); field.value = text;
    field.style.cssText = 'position:fixed;left:-9999px;top:0'; document.body.append(field); field.select();
    let copied = false;
    try { copied = document.execCommand('copy'); } catch (_) {}
    field.remove(); if (active && active.focus) active.focus({preventScroll:true});
    if (copied) { toast('已复制'); return; }
    const dialog = $('copy-dialog'), input = $('manual-copy');
    if (!dialog || !input) return;
    input.value = text;
    if (!dialog.open) dialog.showModal();
    input.focus(); input.select();
  }
  async function copy(text) {
    if (!text) { toast('请先选择需要复制的地址'); return; }
    if (!navigator.clipboard || !window.isSecureContext) { fallbackCopy(text); return; }
    try { await navigator.clipboard.writeText(text); toast('已复制'); }
    catch (_) { fallbackCopy(text); }
  }
  function setupCategories(directory) {
    const panels = [...directory.querySelectorAll('.category-row')];
    const bar = directory.querySelector('.category-tabs');
    if (!panels.length || !bar) return;
    let active = Math.max(0, panels.findIndex(panel => panel.dataset.parent === directory.dataset.currentParent));
    const media = window.matchMedia('(max-width: 700px)');
    const tabs = panels.map((panel, index) => {
      const button = document.createElement('button');
      button.type = 'button'; button.textContent = panel.dataset.name;
      button.id = 'category-tab-' + panel.dataset.parent;
      button.setAttribute('role', 'tab'); button.setAttribute('aria-controls', panel.id);
      button.addEventListener('click', () => select(index, true));
      button.addEventListener('keydown', event => {
        let next = index;
        if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
        else if (event.key === 'ArrowLeft') next = (index + tabs.length - 1) % tabs.length;
        else if (event.key === 'Home') next = 0;
        else if (event.key === 'End') next = tabs.length - 1;
        else return;
        event.preventDefault(); select(next, true); tabs[next].focus({preventScroll:true});
      });
      bar.append(button); return button;
    });
    function select(index, reveal) {
      active = index;
      tabs.forEach((tab, i) => { tab.setAttribute('aria-selected', String(i === active)); tab.tabIndex = i === active ? 0 : -1; });
      panels.forEach((panel, i) => {
        panel.hidden = media.matches && i !== active;
        if (media.matches) { panel.setAttribute('role', 'tabpanel'); panel.setAttribute('aria-labelledby', tabs[i].id); }
        else { panel.removeAttribute('role'); panel.removeAttribute('aria-labelledby'); }
      });
      if (media.matches && reveal) {
        const selected = tabs[active];
        const left = selected.offsetLeft - bar.offsetLeft - (bar.clientWidth - selected.offsetWidth) / 2;
        bar.scrollTo({left, behavior:'auto'});
      }
    }
    bar.setAttribute('role', 'tablist'); bar.setAttribute('aria-orientation', 'horizontal');
    directory.classList.add('has-tabs');
    media.addEventListener('change', () => select(active, true));
    select(active, true);
  }
  document.querySelectorAll('[data-category-directory]').forEach(setupCategories);
  function setFormat(directory, format) {
    directory.dataset.format = format;
    directory.querySelectorAll('[data-format]').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.format === format)));
    directory.querySelector('[data-endpoint-value="main"]').textContent = directory.dataset[format];
    directory.querySelector('[data-endpoint-value="backup"]').textContent = directory.dataset[format + 'Backup'];
  }
  document.querySelectorAll('[data-endpoints]').forEach(directory => setFormat(directory, 'json'));
  function syncGroup(group) {
    const boxes = [...group.querySelectorAll('[data-address-select]')];
    const selected = boxes.filter(box => box.checked).length;
    const all = group.querySelector('[data-select-all]');
    if (all) { all.checked = boxes.length > 0 && selected === boxes.length; all.indeterminate = selected > 0 && selected < boxes.length; }
    const count = group.querySelector('[data-selected-count]');
    if (count) count.textContent = '已选 ' + selected + ' / ' + boxes.length;
  }
  document.querySelectorAll('[data-address-group]').forEach(syncGroup);
  document.addEventListener('change', event => {
    const target = event.target;
    if (target.matches('[data-select-all]')) {
      const group = target.closest('[data-address-group]');
      group.querySelectorAll('[data-address-select]').forEach(box => { box.checked = target.checked; }); syncGroup(group);
    }
    if (target.matches('[data-address-select]')) syncGroup(target.closest('[data-address-group]'));
    if (target.matches('[data-sort-submit]')) {
      const url = new URL(location.href);
      url.searchParams.set('order', target.value); url.searchParams.set('by', 'time'); url.searchParams.set('page', '1');
      // MACCMS merges query parameters after path parameters; page=1 also resets a paginated URL.
      location.assign(url.pathname + url.search + url.hash);
    }
  });
  document.addEventListener('click', event => {
    const target = event.target.closest('button'); if (!target) return;
    if (target.hasAttribute('data-copy')) copy(target.dataset.copy);
    if (target.hasAttribute('data-format')) setFormat(target.closest('[data-endpoints]'), target.dataset.format);
    if (target.hasAttribute('data-endpoint-copy')) {
      const directory = target.closest('[data-endpoints]');
      copy(directory.querySelector('[data-endpoint-value="' + target.dataset.endpointCopy + '"]').textContent);
    }
    if (target.hasAttribute('data-close-dialog')) target.closest('dialog').close();
    if (target.hasAttribute('data-copy-selected')) {
      const group = target.closest('[data-address-group]');
      const addresses = [...group.querySelectorAll('[data-address-row]')].filter(row => row.querySelector('[data-address-select]').checked).map(row => row.querySelector('[data-address-value]').value);
      copy(addresses.join('\n'));
    }
    if (target.hasAttribute('data-reverse')) {
      const group = target.closest('[data-address-group]'), list = group.querySelector('[data-address-list]');
      [...list.children].reverse().forEach(row => list.append(row));
      const reversed = target.getAttribute('aria-pressed') !== 'true';
      target.setAttribute('aria-pressed', String(reversed)); target.textContent = reversed ? '恢复正序' : '倒序排列';
    }
    if (target.hasAttribute('data-report')) {
      if (window.MAC && MAC.Gbook && typeof MAC.Gbook.Report === 'function') {
        MAC.Gbook.Report(target.dataset.report + '，页面地址：' + location.href, target.dataset.reportId);
      } else { toast('报错功能暂不可用，请稍后重试'); }
    }
  });
  if ($('select-copy')) $('select-copy').onclick = () => { $('manual-copy').focus(); $('manual-copy').select(); };
  if ($('density')) $('density').onclick = () => {
    const on = $('density').getAttribute('aria-pressed') !== 'true';
    $('density').setAttribute('aria-pressed', String(on)); $('resources').classList.toggle('compact', on);
  };
  if ($('legacy-toggle')) $('legacy-toggle').onclick = () => { const on = $('legacy').hidden; $('legacy').hidden = !on; $('legacy-toggle').setAttribute('aria-expanded', String(on)); };
  if ($('expand-services')) $('expand-services').onclick = () => {
    const on = $('expand-services').getAttribute('aria-expanded') !== 'true';
    $('expand-services').setAttribute('aria-expanded', String(on)); $('interfaces').classList.toggle('expanded', on);
    $('expand-services').textContent = on ? '收起接口与公告 ⌃' : '展开全部接口与公告 ⌄';
  };
  function imageFallback(image) {
    if (!image.matches('img[data-fallback]')) return;
    const fallback = image.dataset.fallback; image.removeAttribute('data-fallback'); image.src = fallback;
  }
  document.addEventListener('error', event => { if (event.target instanceof HTMLImageElement) imageFallback(event.target); }, true);
  document.querySelectorAll('img[data-fallback]').forEach(image => { if (image.complete && !image.naturalWidth) imageFallback(image); });
})();
