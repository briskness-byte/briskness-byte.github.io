// The Copy button on /embed/. Copies the snippet as text, exactly as shown.
(function () {
'use strict';
const button = document.getElementById('copy');
button.onclick = () => {
    const text = document.getElementById('snippet').textContent;
    navigator.clipboard.writeText(text).then(
        () => { button.textContent = 'Copied'; setTimeout(() => { button.textContent = 'Copy'; }, 2000); },
        () => { button.textContent = 'Select the text and copy it by hand'; });
};
})();
