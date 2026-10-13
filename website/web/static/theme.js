// Light / dark theme. Loaded in <head> (not deferred) so the saved choice is
// applied before the first paint. Choice: auto (follows the system), light or
// dark, saved in localStorage; applied as data-theme on <html> (none = auto).
// The footer button (#theme-toggle) cycles auto -> light -> dark. Doc: doc/web.md
(function () {
  'use strict';

  var KEY = 'urlabuse-theme';
  var ORDER = ['auto', 'light', 'dark'];
  var LABELS = { auto: 'Auto', light: 'Light', dark: 'Dark' };
  var root = document.documentElement;

  var read = function () {
    try {
      var saved = window.localStorage.getItem(KEY);
      return ORDER.indexOf(saved) >= 0 ? saved : 'auto';
    } catch (e) {
      return 'auto';
    }
  };

  var apply = function (choice) {
    if (choice === 'auto') {
      root.removeAttribute('data-theme');
    } else {
      root.setAttribute('data-theme', choice);
    }
  };

  var current = read();
  apply(current);

  document.addEventListener('DOMContentLoaded', function () {
    var button = document.getElementById('theme-toggle');
    if (!button) {
      return;
    }
    var label = button.querySelector('.theme-toggle-label');
    var show = function () {
      button.setAttribute('data-choice', current);
      label.textContent = LABELS[current];
      button.setAttribute('aria-label', 'Colour theme: ' + LABELS[current].toLowerCase() + ' (change)');
    };
    show();
    button.addEventListener('click', function () {
      current = ORDER[(ORDER.indexOf(current) + 1) % ORDER.length];
      try {
        window.localStorage.setItem(KEY, current);
      } catch (e) { /* private mode: the choice lasts for this page only */ }
      apply(current);
      show();
    });
  });
}());
