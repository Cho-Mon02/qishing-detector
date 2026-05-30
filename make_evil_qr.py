import qrcode

# [핵심] 방금 우리가 만든 가짜 네이버 피싱 페이지 주소
# 알고리즘의 3대 필터를 모두 통과(적발)하도록 설계된 주소입니다.
target_url = "http://127.0.0.1:5001/fake_naver_login"

# QR 코드 객체 생성 (디자인 설정)
qr = qrcode.QRCode(
    version=1,
    error_correction=qrcode.constants.ERROR_CORRECT_L,
    box_size=15,
    border=4,
)

qr.add_data(target_url)
qr.make(fit=True)

# 이미지 생성 (검정색 QR, 흰색 배경)
img = qr.make_image(fill_color="black", back_color="white")

# 파일 저장
file_name = "evil_naver_phishing.png"
img.save(file_name)

print(f"✅ 테스트용 악성 QR 코드 생성 완료: {file_name}")
print(f"📍 연결 주소: {target_url}")