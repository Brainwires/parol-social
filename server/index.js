// Privacy overlay
document.getElementById('privacy-link').addEventListener('click', function(e) {
  e.preventDefault();
  document.getElementById('privacy-overlay').classList.add('visible');
});
document.getElementById('privacy-close').addEventListener('click', function() {
  document.getElementById('privacy-overlay').classList.remove('visible');
});
document.getElementById('privacy-overlay').addEventListener('click', function(e) {
  if (e.target === this) this.classList.remove('visible');
});

// Platform detection — show the right instructions
var ua = navigator.userAgent;
var isIOS = /iPhone|iPad|iPod/.test(ua) && !window.MSStream;
var isAndroid = /Android/.test(ua);
var platform = isIOS ? 'ios' : isAndroid ? 'android' : 'desktop';

var el = document.getElementById('steps-' + platform);
if (el) el.classList.add('active');
else document.getElementById('steps-fallback').classList.add('active');
