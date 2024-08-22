from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Image, Paragraph, Spacer
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet
from PIL import Image as PILImage
import datetime
import os
import whois
import socket
import random
import subprocess
from urllib.parse import urlparse

# Генерируем рандомный номер для протокола
protocol_number = ''.join(random.choices('0123456789', k=12))

# Запрос на ввод URL страницы
url = input("Введите URL страницы: ")
parsed_url = urlparse(url)
domain = parsed_url.netloc

# Задаем путь к папке с скриншотами
screenshots_folder = "D:/Programs/Pycharm Proj/Laba1/"

# Создаем экземпляр браузера
driver = webdriver.Edge()

try:
    # Открываем страницу
    driver.get(url)

    # Максимизируем окно браузера для лучшего скриншота
    driver.maximize_window()

    # Ожидаем загрузки элемента body
    wait = WebDriverWait(driver, 10)
    wait.until(EC.presence_of_element_located((By.TAG_NAME, 'body')))

    # Определяем высоту страницы
    total_height = driver.execute_script("return document.body.scrollHeight")

    # Задаем размеры окна браузера, чтобы сделать скриншот всей страницы
    driver.set_window_size(1920, total_height)

    # Прокручиваем страницу и сохраняем скриншоты
    scroll_height = 0
    screenshot_count = 0
    while scroll_height < total_height:
        # Прокручиваем страницу на один экран
        driver.execute_script("window.scrollTo(0, arguments[0]);", scroll_height)
        time.sleep(1)  # Подождем немного после прокрутки
        scroll_height += driver.execute_script("return window.innerHeight;")

        # Сохраняем скриншот
        screenshot_count += 1
        driver.save_screenshot(f"{screenshots_folder}screenshot_{screenshot_count}.png")

    # Создаем PDF файл
    pdf_filename = "screenshots.pdf"
    pdf_path = os.path.join(screenshots_folder, pdf_filename)
    doc = SimpleDocTemplate(pdf_path, pagesize=landscape(letter))

    # Получаем информацию о домене
    domain_info = whois.whois(domain)  # Используем только домен, а не полный URL

    # Извлекаем нужные данные из информации о домене
    if domain_info.domain_name:
        domain_name = domain_info.domain_name
    else:
        domain_name = "N/A"

    if domain_info.registrar:
        registrar = domain_info.registrar
    else:
        registrar = "N/A"

    if domain_info.whois_server:
        whois_server = domain_info.whois_server
    else:
        whois_server = "N/A"

    if domain_info.expiration_date:
        expiration_date = domain_info.expiration_date.strftime("%Y-%m-%d")
    else:
        expiration_date = "N/A"

    if domain_info.updated_date:
        updated_date = domain_info.updated_date.strftime("%Y-%m-%d")
    else:
        updated_date = "N/A"

    if domain_info.status:
        status = domain_info.status
    else:
        status = "N/A"

    if domain_info.name_servers:
        name_servers = domain_info.name_servers
    else:
        name_servers = "N/A"

    if domain_info.emails:
        emails = domain_info.emails
    else:
        emails = "N/A"

    if domain_info.org:
        org = domain_info.org
    else:
        org = "N/A"

    # Собираем список для добавления в PDF
    content = []

    # Создаем стили для заголовков и абзацев
    styles = getSampleStyleSheet()
    title_style = styles["Heading2"]
    title_style.alignment = 1  # Выравнивание по центру
    paragraph_style = styles["BodyText"]

    # Добавляем заголовок
    title_text = f"Protocol {protocol_number} from {datetime.datetime.now().strftime('%Y-%m-%d')} MSK \n\n automated inspection of information on the Internet"
    content.append(Paragraph(title_text, title_style))

    content.append(Paragraph(f"The automated BOBOV 0.1.1 system (hereinafter referred to as the 'System' recorded the following information on the Internet:"))
    content.append(Paragraph(f"1. An Internet page located at: {url}"))

    # Добавляем пустое место для отступа между содержимым заголовка и изображениями
    content.append(Spacer(1, inch * 0.2))

    ip_address = socket.gethostbyname(socket.gethostname())
    content.append(Paragraph(f"Information about the person who initiated the inspection: the user's IP address {ip_address}"))

    # Добавляем пустое место для отступа между содержимым заголовка и изображениями
    content.append(Spacer(1, inch * 0.2))

    content.append(Paragraph(f"Inspection tasks: to record the information posted on the above link(s)."))

    # Добавляем пустое место для отступа между содержимым заголовка и изображениями
    content.append(Spacer(1, inch * 0.2))

    content.append(Paragraph(f"The formation of this protocol began on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} and ended on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} Moscow time. The Protocol is stored in the System database under the unique number {protocol_number}."))

    # Добавляем пустое место для отступа между содержимым заголовка и изображениями
    content.append(Spacer(1, inch * 0.5))

    title_text = f"Appendix 1 to the protocol of automated inspection of information on the Internet No.  {protocol_number} Request for WHOIS information and a technical verification protocol for the {url}"
    content.append(Paragraph(title_text, title_style))

    # Добавляем информацию о домене в список контента для PDF
    content.append(Paragraph(f"domain_name: {domain_name}"))
    content.append(Paragraph(f"registrar: {registrar}"))
    content.append(Paragraph(f"whois_server: {whois_server}"))
    content.append(Paragraph(f"expiration_date: {expiration_date}"))
    content.append(Paragraph(f"updated_date: {updated_date}"))
    content.append(Paragraph(f"status: {status}"))
    content.append(Paragraph(f"name_servers: {name_servers}"))
    content.append(Paragraph(f"emails: {emails}"))
    content.append(Paragraph(f"org: {org}"))

    # Добавляем пустое место для отступа
    content.append(Spacer(1, inch * 0.5))

    # Запуск tracert в Windows
    tracert_result = subprocess.run(['tracert', domain], capture_output=True, text=True)

    # Разбиваем результат tracert на строки
    tracert_lines = tracert_result.stdout.splitlines()

    # Добавляем результаты tracert в список контента для PDF
    content.append(Paragraph("Tracert results:", title_style))
    for line in tracert_lines:
        content.append(Paragraph(line, paragraph_style))

    # Добавляем пустое место для отступа
    content.append(Spacer(1, inch * 0.5))

    # Добавляем изображения в список контента
    for filename in os.listdir(screenshots_folder):
        if filename.endswith(".png"):
            image_path = os.path.join(screenshots_folder, filename)

            # Открываем изображение и изменяем его размер, чтобы оно поместилось на страницу PDF
            img = PILImage.open(image_path)
            max_width, max_height = letter
            if img.width > max_width or img.height > max_height:
                img.thumbnail((max_width, max_height))

            # Создаем объект изображения для добавления в PDF
            rl_img = Image(image_path, width=img.width, height=img.height)
            content.append(rl_img)

    # Добавляем содержимое в PDF
    doc.build(content)

    print(f"PDF файл успешно создан: {pdf_path}")

finally:
    # Закрываем браузер
    driver.quit()
