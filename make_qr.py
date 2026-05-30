import qrcode

# 계획서 테스트용 가짜 피싱 URL 주소
test_url = "http://127.0.0.1:5001/phish_check"

# QR 코드 객체 생성
qr = qrcode.QRCode(box_size=10, border=4)
qr.add_data(test_url)
qr.make(fit=True)

# 이미지로 저장
img = qr.make_image(fill_color="black", back_color="white")
img.save("real_test_qr.png")
print("real_test_qr.png 파일이 생성되었습니다!")