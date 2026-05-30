from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import cv2
import numpy as np
from pyzbar.pyzbar import decode
import base64
import re
from datetime import datetime
import requests

app = Flask(__name__)

# [MariaDB 연결 설정] - 오타 교정 완료!
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:secu1234@localhost/qshield_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# [DB 테이블 구조 정의]
class ScanLog(db.Model):
    __tablename__ = 'scan_logs'
    
    id = db.Column(db.Integer, primary_key=True)      
    url = db.Column(db.String(500), nullable=False)   
    risk_score = db.Column(db.Integer, nullable=False)
    risk_status = db.Column(db.String(50), nullable=False) 
    timestamp = db.Column(db.DateTime, default=datetime.now) 

    def __init__(self, url, risk_score, risk_status):
        self.url = url
        self.risk_score = risk_score
        self.risk_status = risk_status

@app.route('/')
def index():
    # 메인 화면 진입 시 DB에서 최신 로그 5개를 들고 감 (이력 탭용)
    recent_logs = ScanLog.query.order_by(ScanLog.timestamp.desc()).limit(5).all()
    return render_template('index.html', logs=recent_logs)

# [5주차 핵심 URL 위험도 분석 알고리즘]
def analyze_url(url):
    risk_score = 0
    reasons = []

    # ─── [ 단축 URL 우회 및 원본 추적 ] ───
    short_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'me2.do']
    is_shortened = any(domain in url.lower() for domain in short_domains)

    if is_shortened:
        risk_score += 25
        reasons.append("추적을 회피하기 위해 단축 URL(Short URL)을 사용하고 있습니다.")
        try:
            # 실시간으로 가짜 요청을 보내 리다이렉트되는 최종 목적지 주소를 알아냅니다.
            response = requests.head(url, allow_redirects=True, timeout=3)
            url = response.url # url 변수를 '진짜 원본 주소'로 교체!
            reasons.append(f"➔ [우회 추적 완료] 숨겨진 실제 목적지: {url}")
        except:
            reasons.append("➔ [추적 실패] 단축 URL의 원본 주소를 추적하는 도중 연결이 끊겼습니다.")

    # 1 필터: IP 주소 검사
    if re.search(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', url):
        risk_score += 40
        reasons.append("도메인 대신 추적이 어려운 숫자 IP 주소를 직접 사용하고 있습니다.")
        
    # 2 필터: 피싱 키워드 검사
    suspicious_keywords = ['login', 'verify', 'bank', 'update', 'phish', 'check']
    for word in suspicious_keywords:
        if word in url.lower():
            risk_score += 30
            reasons.append(f"사용자 기만을 위한 피싱 의심 단어('{word}')가 URL에 포함되어 있습니다.")
            
    # 3 필터: HTTP 프로토콜 검사
    if url.lower().startswith("http://"):
        risk_score += 20
        reasons.append("데이터 암호화가 지원되지 않는 안전하지 않은 연결(HTTP)을 사용 중입니다.")
        
    if risk_score >= 60:
        status = "🚨 위험 (피싱 의심 사이트)"
        color = "#dc3545"
    elif risk_score >= 20:
        status = "⚠️ 주의 (정밀 확인 필요)"
        color = "#ffc107"
    else:
        status = "✅ 안전 (정상 주소)"
        color = "#198754"
        
    return {'score': risk_score, 'status': status, 'color': color, 'reasons': reasons}

# [통로 1: 실시간 비디오 프레임 스캔 엔진]
@app.route('/scan_frame', methods=['POST'])
def scan_frame():
    data = request.get_json()
    if not data or 'image' not in data:
        return jsonify({'success': False})
    
    try:
        image_data = data['image'].split(',')[1]
        decoded_data = base64.b64decode(image_data)
        np_data = np.frombuffer(decoded_data, np.uint8)
        img = cv2.imdecode(np_data, cv2.IMREAD_COLOR)
        
        if img is None:
            return jsonify({'success': False})

        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        decoded_objects = decode(gray) or decode(img)
            
        if decoded_objects:
            extracted_url = decoded_objects[0].data.decode('utf-8')
            analysis = analyze_url(extracted_url)
            
            # DB 로그 저장
            new_log = ScanLog(url=extracted_url, risk_score=analysis['score'], risk_status=analysis['status'])
            db.session.add(new_log)
            db.session.commit()
            
            return jsonify({'success': True, 'url': extracted_url, 'analysis': analysis})
        return jsonify({'success': False})
    except:
        return jsonify({'success': False})

# [통로 2: 직접 고른 파일 이미지 검사 엔진 + OpenCV 고도화 필터]
@app.route('/upload_file_api', methods=['POST'])
def upload_file_api():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': '파일이 없습니다.'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': '선택된 파일이 없습니다.'})
    
    try:
        file_bytes = np.frombuffer(file.read(), np.uint8)
        orig_img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
        
        if orig_img is None:
            return jsonify({'success': False, 'message': '이미지 디코딩 실패'})

        h, w = orig_img.shape[:2]
        max_size = 1024
        if max(h, w) > max_size:
            scale = max_size / max(h, w)
            img = cv2.resize(orig_img, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_AREA)
        else:
            img = orig_img.copy()

        decoded_objects = decode(img)

        if not decoded_objects:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            decoded_objects = decode(gray)

        if not decoded_objects:
            blurred = cv2.GaussianBlur(gray, (5, 5), 0)
            processed_img = cv2.adaptiveThreshold(
                blurred, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 21, 7
            )
            decoded_objects = decode(processed_img)

        if not decoded_objects:
            kernel = np.array([[0, -1, 0], [-1, 5, -1], [0, -1, 0]])
            sharpened = cv2.filter2D(gray, -1, kernel)
            decoded_objects = decode(sharpened)

        if decoded_objects:
            extracted_url = decoded_objects[0].data.decode('utf-8')
            analysis = analyze_url(extracted_url)
            
            # DB 로그 저장
            new_log = ScanLog(url=extracted_url, risk_score=analysis['score'], risk_status=analysis['status'])
            db.session.add(new_log)
            db.session.commit()
            
            return jsonify({'success': True, 'url': extracted_url, 'analysis': analysis})
        
        return jsonify({'success': False, 'message': 'QR 코드를 인식하지 못했습니다.'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
# ─── [ 모의 해킹용 가짜 피싱 웹페이지 ] ───
@app.route('/fake_naver_login')
def fake_naver_login():
    # 실제 피싱 사이트처럼 보이도록 그럴싸한 경고 문구와 함께 템플릿을 띄웁니다.
    return render_template('fake_login.html')
    
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)