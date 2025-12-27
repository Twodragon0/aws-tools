#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GuardDuty Lambda Function
AWS GuardDuty findings를 Slack으로 전송하는 Lambda 함수.

보안 고려사항:
- Webhook URL은 환경 변수에서 읽기 (하드코딩 금지)
- 예외 처리 및 로깅
- 민감한 정보 로깅 방지
"""

import os
import sys
import json
import logging
import requests
import datetime
from typing import Dict, Any, Optional

try:
    import exception_function
except ImportError:
    exception_function = None

# 로깅 설정
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# 기존 핸들러 제거
for handler in logger.handlers[:]:
    logger.removeHandler(handler)

# 콘솔 핸들러 추가
console_handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('[%(levelname)s]/%(asctime)s/%(name)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


def format_time(event_time: str) -> str:
    """
    이벤트 시간을 KST로 변환합니다.
    
    Args:
        event_time: ISO 8601 형식의 시간 문자열
        
    Returns:
        KST로 변환된 시간 문자열
    """
    try:
        event_time = event_time.split("T")
        date = event_time[0]
        time_part = event_time[1].split(".")[0]
        ret_time = f"{date} {time_part}"
        ret_time = datetime.datetime.strptime(ret_time, '%Y-%m-%d %H:%M:%S')
        ret_time = ret_time + datetime.timedelta(hours=9)  # UTC -> KST
        return str(ret_time)
    except (ValueError, IndexError) as e:
        logger.warning(f"시간 파싱 실패: {event_time}, 오류: {e}")
        return event_time


def get_severity_color(severity: float) -> str:
    """
    심각도에 따른 색상 반환
    
    Args:
        severity: GuardDuty 심각도 (0-10)
        
    Returns:
        Slack 색상 코드
    """
    if severity >= 7:
        return 'danger'
    elif severity >= 4:
        return 'warning'
    else:
        return 'good'


def build_console_url(region: str, message_id: str) -> str:
    """
    GuardDuty 콘솔 URL 생성
    
    Args:
        region: AWS 리전
        message_id: GuardDuty Finding ID
        
    Returns:
        콘솔 URL
    """
    base_url = "https://console.aws.amazon.com/guardduty/home?region="
    return f"{base_url}{region}#findings?search=id%3D{message_id}"


def push_to_slack(event: Dict[str, Any]) -> str:
    """
    GuardDuty Finding을 Slack으로 전송합니다.
    
    Args:
        event: Lambda 이벤트 객체
        
    Returns:
        성공 메시지
    """
    event_detail = event.get('detail', {})
    
    # 예외 처리 함수 호출 (있는 경우)
    if exception_function:
        try:
            if exception_function.exception(event_detail, exception_function.condition):
                logger.info("예외 조건에 해당하여 Slack 전송을 건너뜁니다.")
                return "Skipped due to exception condition"
        except Exception as e:
            logger.warning(f"예외 함수 처리 중 오류: {e}")

 
    
    try:
        # 이벤트 데이터 추출 (안전한 접근)
        finding = event_detail.get("type", "Unknown")
        message_id = event_detail.get("id", "N/A")
        region = event_detail.get("region", "N/A")
        finding_description = event_detail.get("description", "No description")
        severity = float(event_detail.get("severity", 0))
        updated_at = format_time(event_detail.get("updatedAt", ""))
        count = event_detail.get("service", {}).get("count", 0)
        console_url = build_console_url(region, message_id)
        
        # Slack 메시지 페이로드 생성
        slack_payload = {
            "attachments": [
                {
                    "fallback": f"Finding - {console_url}",
                    "pretext": f"*Finding ID: {message_id}*",
                    "title": finding,
                    "title_link": console_url,
                    "text": finding_description,
                    "fields": [
                        {"title": "Severity", "value": str(severity), "short": True},
                        {"title": "Region", "value": region, "short": True},
                        {"title": "UpdatedAt", "value": updated_at, "short": True},
                        {"title": "Count", "value": str(count), "short": True}
                    ],
                    "mkdwn_in": ["pretext"],
                    "color": get_severity_color(severity),
                }
            ]
        }    

        # 보안: Webhook URL은 환경 변수에서 읽기 (하드코딩 금지)
        if "sample" in event.get("service", {}).get("additionalInfo", {}):
            if event["service"]["additionalInfo"].get("sample") is True:
                # Test Channel URL
                webhook_url = os.getenv('SLACK_WEBHOOK_URL_TEST', '')
            else:
                # DEV Channel URL
                webhook_url = os.getenv('SLACK_WEBHOOK_URL_DEV', '')
        else:
            # Production Channel URL
            webhook_url = os.getenv('SLACK_WEBHOOK_URL_PROD', '')
        
        if not webhook_url:
            logger.error("Slack webhook URL이 설정되지 않았습니다. 환경 변수를 확인하세요.")
            raise ValueError("SLACK_WEBHOOK_URL 환경 변수가 설정되지 않았습니다.")
        
        # HTTP 요청 타임아웃 설정
        response = requests.post(
            webhook_url,
            data=json.dumps(slack_payload),
            headers={'Content-Type': 'application/json'},
            timeout=10  # 타임아웃 추가
        )
        
        # 응답 상태 코드 확인
        if response.status_code != 200:
            logger.error(f'Slack 요청 실패: {response.status_code} - {response.text}')
            raise ValueError(f'Slack webhook 요청 실패: {response.status_code}')

        logger.info('SUCCESS: Pushed GuardDuty Finding to Slack')
        return "Successfully pushed notification to Slack"
        
    except KeyError as e:
        logger.error(f'ERROR: Unable to push to Slack: Missing key {e}')
        logger.error('Check: [1] Slack Webhook URL is valid, [2] IAM Role Permissions')
        raise
    except requests.exceptions.RequestException as e:
        logger.error(f'ERROR: HTTP request failed: {e}')
        raise
    except Exception as e:
        logger.error(f'ERROR: Unexpected error: {e}')
        raise


def lambda_handler(event: Dict[str, Any], context: Any) -> str:
    """
    Lambda 핸들러 함수
    
    Args:
        event: Lambda 이벤트 객체
        context: Lambda 컨텍스트 객체
        
    Returns:
        처리 결과 메시지
    """
    try:
        return push_to_slack(event)
    except Exception as e:
        logger.error(f"Lambda 핸들러 오류: {e}")
        raise

if __name__ == '__main__':
    lambda_handler(None, None)
