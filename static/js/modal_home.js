document.addEventListener('DOMContentLoaded', () => {
    const menuButton = document.getElementById('menu-button');
    const modal = document.getElementById('modal-nav');
    const closeButton = modal.querySelector('.close-btn');

    // Открытие модального окна
    menuButton.addEventListener('click', () => {
    modal.classList.remove('hidden');
    document.body.classList.add('modal-open');
    });

    // Закрытие модального окна
    closeButton.addEventListener('click', () => {
    modal.classList.add('hidden');
    document.body.classList.remove('modal-open');
    });

    // Закрытие модального окна при клике вне его
 window.addEventListener('click', (event) => {
    if (event.target === modal) {
        modal.classList.add('hidden');
        document.body.classList.remove('modal-open');
    }
    });
});