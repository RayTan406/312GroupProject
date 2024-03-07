function backgroundChangeToRed() {
    document.body.style.backgroundColor = "red";
}
function backgroundChangeToBlue() {
    document.body.style.backgroundColor = "#87d6d4";
}

document.getElementById("background_buttonred").addEventListener('click', backgroundChangeToRed(), false);
document.getElementById("background_buttonblue").addEventListener('click', backgroundChangeToBlue(), false);