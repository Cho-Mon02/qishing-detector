import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

print("🔄 데이터셋 로드 중...")
df = pd.read_csv('malicious_phish.csv')

# 시간 관계상 샘플 5만 개만 추출해서 고속 검증 수행
df_sample = df.sample(n=50000, random_state=42)

# 특성 변환
def extract_features(url):
    if not isinstance(url, str): 
        url = ""
    
    # [기존 5대 특성]
    url_len = len(url)
    dot_count = url.count('.')
    hyphen_count = url.count('-')
    digit_count = sum(c.isdigit() for c in url)
    
    suspicious_keywords = ['login', 'verify', 'bank', 'update', 'phish', 'check', 'secure', 'naver', 'daum', 'kakao']
    keyword_count = sum(1 for word in suspicious_keywords if word in url.lower())
    
    # ─── [ 🌟 정확도 치트키: 신규 특성 3개 추가 ] ───
    # 6. 슬래시(/) 개수 : 피싱 사이트는 주소 뒤에 경로를 길게 뺍니다.
    slash_count = url.count('/')
    
    # 7. 서브 도메인 여부 (www. 제외하고 점이 2개 이상인지)
    # 예: signin.ebay.com.badsite.com 처럼 주소를 속이는 패턴 방어
    has_subdomain = 1 if url.replace("www.", "").count('.') >= 2 else 0
    
    # 8. 안전 프로토콜(https) 미사용 여부 (HTTP 우려 환경 점검)
    is_http = 1 if url.lower().startswith("http://") else 0
    # ────────────────────────────────────────────────
    
    # 총 8개의 힌트를 배열로 반환합니다.
    return [url_len, dot_count, hyphen_count, digit_count, keyword_count, slash_count, has_subdomain, is_http]
    
X = np.array(df_sample['url'].apply(extract_features).tolist())
y = np.where(df_sample['type'] == 'benign', 0, 1)

# 🌟 중요: 데이터를 80%는 공부용(Train), 20%는 시험용(Test)으로 쪼갭니다!
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print(f"🌲 훈련 데이터 세트: {len(X_train)}개 | 시험 문제 세트: {len(X_test)}개")

# 모델 학습
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# 💯 시험 문제 세트 풀게 하기
y_pred = model.predict(X_test)

# 결과 성적표 출력
print("\n================== 🎯 AI 탐지 성적표 ==================")
print(f"▶️ 전체 탐지 정확도 (Accuracy): {accuracy_score(y_test, y_pred) * 100:.2f}%")
print("------------------------------------------------------")
print(classification_report(y_test, y_pred, target_names=['정상(Clean)', '악성(Malicious)']))
print("======================================================")