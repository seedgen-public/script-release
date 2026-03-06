#!/bin/bash
#================================================================
# Nginx_Linux 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : Nginx_Linux
# 항목  : WEB-01 ~ WEB-26 (26개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

# Nginx 설치 경로 (자동 탐지 실패 시 수동 설정)
NGINX_HOME=""
NGINX_CONF=""

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="Nginx"
META_TYPE="WEB"

# 권한 체크
if [ "$EUID" -ne 0 ]; then
    echo "[!] root 권한으로 실행하세요."
    exit 1
fi

# XML 특수문자 이스케이프
xml_escape() {
    local s="$1"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    s="${s//\"/&quot;}"
    echo "$s"
}

# 결과 출력 함수
output_checkpoint() {
    local CODE="$1"
    local CAT="$2"
    local NAME="$3"
    local IMP="$4"
    local STD="$5"
    local RES="$6"
    local DESC="$7"
    local DT="$8"

    case "$RES" in
        "Y")   echo -e "    [\033[32mY\033[0m] $CODE $NAME" ;;
        "N")   echo -e "    [\033[31mN\033[0m] $CODE $NAME" ;;
        "M")   echo -e "    [\033[33mM\033[0m] $CODE $NAME" ;;
        "N/A") echo -e "    [\033[90m-\033[0m] $CODE $NAME" ;;
        *)     echo -e "    [-] $CODE $NAME" ;;
    esac

    local E_NAME; E_NAME=$(xml_escape "$NAME")
    local E_DESC; E_DESC=$(xml_escape "$DESC")
    local E_STD; E_STD=$(xml_escape "$STD")
    cat >> "$OUTPUT_FILE" << CPEOF
        <cp>
            <code>$CODE</code>
            <cat>$CAT</cat>
            <n>$E_NAME</n>
            <imp>$IMP</imp>
            <std>$E_STD</std>
            <res>$RES</res>
            <desc>$E_DESC</desc>
            <dt><![CDATA[$DT]]></dt>
        </cp>
CPEOF
}

#================================================================
# COLLECT
#================================================================
META_DATE=$(date +%Y-%m-%dT%H:%M:%S%:z)
SYS_HOST=$(hostname)
SYS_DOM=$(hostname -d 2>/dev/null || echo "N/A")
SYS_OS_NAME=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2)
SYS_OS_FN=$(echo "$SYS_OS_NAME" | sed 's/ (.*)//g')
SYS_KN=$(uname -r)
SYS_ARCH=$(uname -m)
SYS_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
SYS_NET_ALL=$(ip -4 addr show 2>/dev/null | grep inet | awk '{print $NF": "$2}' | cut -d'/' -f1)

#================================================================
# DETECT — 플랫폼별 커스터마이즈 영역
# (서비스 탐지, 설정파일 경로, 버전 정보)
#================================================================
# Nginx 설치 경로 자동 탐지
detect_nginx() {
    local NGINX_BIN=""

    # nginx 바이너리 찾기
    if command -v nginx &>/dev/null; then
        NGINX_BIN=$(command -v nginx)
    elif [ -x "/usr/sbin/nginx" ]; then
        NGINX_BIN="/usr/sbin/nginx"
    elif [ -x "/usr/local/nginx/sbin/nginx" ]; then
        NGINX_BIN="/usr/local/nginx/sbin/nginx"
    fi

    if [ -n "$NGINX_BIN" ]; then
        # 설정 파일 경로 추출
        NGINX_CONF=$($NGINX_BIN -t 2>&1 | grep "configuration file" | head -1 | sed 's/.*configuration file //;s/ .*//')

        if [ -z "$NGINX_CONF" ] || [ ! -f "$NGINX_CONF" ]; then
            # -V 옵션으로 기본 설정 파일 경로 확인
            NGINX_CONF=$($NGINX_BIN -V 2>&1 | grep -oP '(?<=--conf-path=)[^\s]+')
        fi

        # NGINX_HOME 설정
        if [ -n "$NGINX_CONF" ] && [ -f "$NGINX_CONF" ]; then
            NGINX_HOME=$(dirname "$(dirname "$NGINX_CONF")")
        fi
    fi

    # 일반적인 경로에서 찾기
    if [ -z "$NGINX_CONF" ] || [ ! -f "$NGINX_CONF" ]; then
        local COMMON_PATHS=(
            "/etc/nginx/nginx.conf"
            "/usr/local/nginx/conf/nginx.conf"
            "/opt/nginx/conf/nginx.conf"
            "/usr/local/etc/nginx/nginx.conf"
        )
        for path in "${COMMON_PATHS[@]}"; do
            if [ -f "$path" ]; then
                NGINX_CONF="$path"
                NGINX_HOME=$(dirname "$(dirname "$NGINX_CONF")")
                break
            fi
        done
    fi
}

# Nginx 탐지 실행
detect_nginx

# include 디렉티브로 포함되는 모든 설정 파일 경로 수집
# 반환: 공백으로 구분된 설정 파일 경로 목록
get_all_config_paths() {
    local PATHS=""

    # 메인 설정 파일 디렉터리
    if [ -n "$NGINX_CONF" ] && [ -f "$NGINX_CONF" ]; then
        PATHS="$(dirname "$NGINX_CONF")"
    fi

    # 추가 설정 디렉터리 (include로 포함될 수 있는 경로들)
    local EXTRA_DIRS=(
        "/etc/nginx/sites-enabled"
        "/etc/nginx/sites-available"
        "/etc/nginx/conf.d"
        "/etc/nginx/modules-enabled"
        "/usr/local/nginx/conf/sites-enabled"
        "/usr/local/nginx/conf/conf.d"
    )

    for dir in "${EXTRA_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            PATHS="$PATHS $dir"
        fi
    done

    echo "$PATHS"
}

# 모든 설정 경로에서 패턴 검색 (grep wrapper)
# 사용법: search_all_configs "pattern" [추가grep옵션]
search_all_configs() {
    local PATTERN="$1"
    shift
    local EXTRA_OPTS="$@"
    local RESULT=""
    local CONFIG_PATHS=$(get_all_config_paths)

    for path in $CONFIG_PATHS; do
        if [ -d "$path" ]; then
            local FOUND=$(grep -rE "$PATTERN" "$path" --include="*.conf" $EXTRA_OPTS 2>/dev/null | grep -v "^\s*#")
            if [ -n "$FOUND" ]; then
                [ -n "$RESULT" ] && RESULT="$RESULT\n"
                RESULT="$RESULT$FOUND"
            fi
        fi
    done

    echo -e "$RESULT"
}

# Nginx 버전 정보
NGINX_VERSION=""
if command -v nginx &>/dev/null; then
    NGINX_VERSION=$(nginx -v 2>&1)
fi

SVC_VERSION="$NGINX_VERSION"
SVC_CONF="$NGINX_CONF"

# 출력 파일 경로
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_FILE="${SCRIPT_DIR}/${META_PLAT}_${SYS_HOST}_$(date +%Y%m%d_%H%M%S).xml"

#================================================================
# CHECK FUNCTIONS
#================================================================

check01() {
    local CODE="WEB-01"
    local CAT="계정관리"
    local NAME="Default 관리자 계정명 변경"
    local IMP="상"
    local STD="관리자 페이지를 사용하지 않거나, 계정명이 기본 계정명으로 설정되어 있지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Nginx는 별도의 관리자 계정이 없음 (설정 파일 기반 운영)"
    local DT="Nginx는 별도의 관리 콘솔이나 관리자 계정을 사용하지 않습니다.\n설정 파일(nginx.conf)을 직접 편집하여 운영하므로 해당 점검 항목은 N/A 처리됩니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check02() {
    local CODE="WEB-02"
    local CAT="계정관리"
    local NAME="취약한 비밀번호 사용 제한"
    local IMP="상"
    local STD="관리자 비밀번호가 암호화되어 있거나, 유추하기 어려운 비밀번호로 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="해당 없음 (Nginx는 별도의 내장 인증 계정이 없음)"
    local DT="Nginx는 자체적인 사용자 인증 계정 시스템을 제공하지 않습니다.\nBasic 인증 사용 시 htpasswd 파일로 관리하며, 이는 WEB-03에서 점검합니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check03() {
    local CODE="WEB-03"
    local CAT="계정관리"
    local NAME="비밀번호 파일 권한 관리"
    local IMP="상"
    local STD="비밀번호 파일에 권한이 600 이하로 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Nginx는 별도의 비밀번호 파일이 없음"
    local DT="Nginx는 자체적인 비밀번호 파일을 사용하지 않습니다.\nBasic 인증 사용 시 htpasswd 파일은 별도 관리가 필요하며,\n해당 점검 항목은 N/A 처리됩니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check04() {
    local CODE="WEB-04"
    local CAT="서비스관리"
    local NAME="웹 서비스 디렉터리 리스팅 방지 설정"
    local IMP="상"
    local STD="디렉터리 리스팅이 설정되지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$NGINX_CONF" ] || [ ! -f "$NGINX_CONF" ]; then
        RES="N/A"
        DESC="Nginx 설정 파일을 찾을 수 없음"
        DT="NGINX_CONF: not found"
    else
        # autoindex on 설정 확인 (모든 설정 파일에서)
        local AUTOINDEX_ON=$(search_all_configs "^\s*autoindex\s+on")

        if [ -z "$AUTOINDEX_ON" ]; then
            RES="Y"
            DESC="디렉터리 리스팅이 비활성화되어 있음"
            DT="autoindex: off (기본값) 또는 미설정"
        else
            RES="N"
            DESC="디렉터리 리스팅이 활성화되어 있음"
            DT="발견된 설정:\n$AUTOINDEX_ON"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check05() {
    local CODE="WEB-05"
    local CAT="서비스관리"
    local NAME="지정하지 않은 CGI/ISAPI 실행 제한"
    local IMP="상"
    local STD="CGI 스크립트를 사용하지 않거나 CGI 스크립트가 실행 가능한 디렉터리를 제한한 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$NGINX_CONF" ] || [ ! -f "$NGINX_CONF" ]; then
        RES="N/A"
        DESC="Nginx 설정 파일을 찾을 수 없음"
        DT="NGINX_CONF: not found"
    else
        # FastCGI 설정 확인 (모든 설정 파일에서)
        local FASTCGI_PASS=$(search_all_configs "^\s*fastcgi_pass")

        # CGI 관련 location 블록 확인
        local CGI_LOCATION=$(search_all_configs "^\s*location.*\.cgi")

        local DETAILS=""
        [ -n "$FASTCGI_PASS" ] && DETAILS="FastCGI 설정:\n$FASTCGI_PASS\n"
        [ -n "$CGI_LOCATION" ] && DETAILS="${DETAILS}CGI Location:\n$CGI_LOCATION"

        if [ -z "$FASTCGI_PASS" ] && [ -z "$CGI_LOCATION" ]; then
            RES="Y"
            DESC="CGI/FastCGI 실행이 제한되어 있음"
            DT="fastcgi_pass: 미설정\nCGI location: 미설정"
        elif [ -n "$FASTCGI_PASS" ] || [ -n "$CGI_LOCATION" ]; then
            RES="M"
            DESC="CGI/FastCGI 설정 확인 필요"
            DT="$DETAILS"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check06() {
    local CODE="WEB-06"
    local CAT="서비스관리"
    local NAME="웹 서비스 상위 디렉터리 접근 제한 설정"
    local IMP="상"
    local STD="상위 디렉터리 접근 기능을 제거한 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$NGINX_CONF" ] || [ ! -f "$NGINX_CONF" ]; then
        RES="N/A"
        DESC="Nginx 설정 파일을 찾을 수 없음"
        DT="NGINX_CONF: not found"
    else
        # auth_basic 설정 확인 (기본 인증을 통한 디렉터리 접근 제한)
        local AUTH_BASIC=$(search_all_configs "^\s*auth_basic\s+" | grep -v "auth_basic\s+off")
        local AUTH_BASIC_USER_FILE=$(search_all_configs "^\s*auth_basic_user_file")

        # location 블록에서 deny/allow 설정 확인
        local ACCESS_CONTROL=$(search_all_configs "^\s*(deny|allow)\s+" | head -10)

        if [ -n "$AUTH_BASIC" ] && [ -n "$AUTH_BASIC_USER_FILE" ]; then
            RES="Y"
            DESC="상위 디렉터리 접근 제한이 설정됨 (기본 인증)"
            DT="auth_basic 설정:\n$AUTH_BASIC\nauth_basic_user_file:\n$AUTH_BASIC_USER_FILE"
        elif [ -n "$ACCESS_CONTROL" ]; then
            RES="M"
            DESC="접근 제어 설정 존재 (수동 확인 필요)"
            DT="접근 제어 설정:\n$ACCESS_CONTROL"
        else
            RES="M"
            DESC="접근 제한 설정이 없음 (수동 확인 필요)"
            DT="auth_basic: 미설정\ndeny/allow: 미설정"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check07() {
    local CODE="WEB-07"
    local CAT="서비스관리"
    local NAME="웹 서비스 경로 내 불필요한 파일 제거"
    local IMP="중"
    local STD="기본으로 생성되는 불필요한 파일 및 디렉터리가 존재하지 않을 경우"
    local RES=""
    local DESC=""
    local DT=""

    # Nginx 기본 HTML 디렉터리 확인
    local HTML_PATHS=(
        "/usr/share/nginx/html"
        "/var/www/html"
        "/usr/local/nginx/html"
        "/opt/nginx/html"
    )

    local FOUND_FILES=""
    local FOUND_PATH=""

    for path in "${HTML_PATHS[@]}"; do
        if [ -d "$path" ]; then
            FOUND_PATH="$path"
            # 기본 index.html, 50x.html 등 확인
            if [ -f "$path/index.html" ]; then
                local CONTENT=$(grep -i "welcome to nginx" "$path/index.html" 2>/dev/null)
                [ -n "$CONTENT" ] && FOUND_FILES="$FOUND_FILES\n$path/index.html (기본 페이지)"
            fi
            # 불필요한 파일 확인
            local UNNECESSARY=$(find "$path" -type f \( -name "*.bak" -o -name "*.backup" -o -name "*.old" -o -name "*.tmp" -o -name "*.swp" -o -name "README*" \) 2>/dev/null | head -10)
            [ -n "$UNNECESSARY" ] && FOUND_FILES="$FOUND_FILES\n$UNNECESSARY"
            break
        fi
    done

    if [ -z "$FOUND_FILES" ]; then
        RES="Y"
        DESC="불필요한 파일이 없음"
        DT="HTML 디렉터리: ${FOUND_PATH:-없음}\n불필요 파일: 없음"
    else
        RES="N"
        DESC="불필요한 파일 또는 기본 페이지가 존재함"
        DT="발견된 파일:$FOUND_FILES"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check08() {
    local CODE="WEB-08"
    local CAT="서비스관리"
    local NAME="웹 서비스 파일 업로드 및 다운로드 용량 제한"
    local IMP="하"
    local STD="파일 업로드 및 다운로드 용량을 제한한 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$NGINX_CONF" ] || [ ! -f "$NGINX_CONF" ]; then
        RES="N/A"
        DESC="Nginx 설정 파일을 찾을 수 없음"
        DT="NGINX_CONF: not found"
    else
        # client_max_body_size 설정 확인 (모든 설정 파일에서)
        local MAX_BODY_SIZE=$(search_all_configs "^\s*client_max_body_size")

        if [ -n "$MAX_BODY_SIZE" ]; then
            # 0 값 확인 (무제한 설정 - 취약)
            local ZERO_SIZE=$(echo "$MAX_BODY_SIZE" | grep -E "client_max_body_size\s+0\s*;")

            if [ -n "$ZERO_SIZE" ]; then
                RES="N"
                DESC="파일 업로드 용량이 무제한으로 설정됨"
                DT="$MAX_BODY_SIZE\n\n[취약] client_max_body_size 0은 무제한을 의미합니다."
            else
                RES="Y"
                DESC="파일 업로드 용량 제한이 설정됨"
                DT="$MAX_BODY_SIZE"
            fi
        else
            RES="N"
            DESC="파일 업로드 용량 제한이 설정되지 않음"
            DT="client_max_body_size: 미설정 (기본값: 1MB)"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check09() {
    local CODE="WEB-09"
    local CAT="서비스관리"
    local NAME="웹 서비스 프로세스 권한 제한"
    local IMP="상"
    local STD="웹 프로세스(웹 서비스)가 관리자 권한이 부여된 계정이 아닌 운영에 필요한 최소한의 권한을 가진 별도의 계정으로 구동되고 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

    # Nginx 워커 프로세스 실행 계정 확인
    local NGINX_USER=$(ps aux 2>/dev/null | grep "nginx: worker" | grep -v grep | awk '{print $1}' | sort -u | head -1)

    # 설정 파일에서 user 지시자 확인
    local CONF_USER=""
    if [ -n "$NGINX_CONF" ] && [ -f "$NGINX_CONF" ]; then
        CONF_USER=$(grep -E "^\s*user\s+" "$NGINX_CONF" 2>/dev/null | grep -v "^\s*#" | awk '{print $2}' | tr -d ';')
    fi

    local CHECK_USER="${NGINX_USER:-$CONF_USER}"

    if [ -z "$CHECK_USER" ]; then
        RES="M"
        DESC="Nginx 실행 계정을 확인할 수 없음"
        DT="실행 중인 프로세스: 없음\n설정 파일 user: ${CONF_USER:-미설정}"
    elif [ "$CHECK_USER" = "root" ]; then
        RES="N"
        DESC="Nginx 워커 프로세스가 root 권한으로 실행 중"
        DT="실행 계정: $CHECK_USER"
    else
        RES="Y"
        DESC="Nginx가 제한된 권한으로 실행 중"
        DT="실행 계정: $CHECK_USER\n설정 user: ${CONF_USER:-미설정}"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check10() {
    local CODE="WEB-10"
    local CAT="서비스관리"
    local NAME="불필요한 프록시 설정 제한"
    local IMP="상"
    local STD="불필요한 Proxy 설정을 제한한 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$NGINX_CONF" ] || [ ! -f "$NGINX_CONF" ]; then
        RES="N/A"
        DESC="Nginx 설정 파일을 찾을 수 없음"
        DT="NGINX_CONF: not found"
    else
        # proxy_pass 설정 확인 (모든 설정 파일에서)
        local PROXY_PASS=$(search_all_configs "^\s*proxy_pass")

        # upstream 설정 확인
        local UPSTREAM=$(search_all_configs "^\s*upstream\s+")

        local DETAILS=""
        [ -n "$PROXY_PASS" ] && DETAILS="proxy_pass:\n$PROXY_PASS\n"
        [ -n "$UPSTREAM" ] && DETAILS="${DETAILS}upstream:\n$UPSTREAM"

        if [ -z "$PROXY_PASS" ] && [ -z "$UPSTREAM" ]; then
            RES="Y"
            DESC="프록시 설정이 비활성화되어 있음"
            DT="proxy_pass: 미설정\nupstream: 미설정"
        else
            RES="M"
            DESC="프록시 설정 확인 필요 (Reverse Proxy 사용 시 양호)"
            DT="$DETAILS"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check11() {
    local CODE="WEB-11"
    local CAT="서비스관리"
    local NAME="웹 서비스 경로 설정"
    local IMP="중"
    local STD="웹 서버 경로를 기타 업무와 영역이 분리된 경로로 설정 및 불필요한 경로가 존재하지 않는 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$NGINX_CONF" ] || [ ! -f "$NGINX_CONF" ]; then
        RES="N/A"
        DESC="Nginx 설정 파일을 찾을 수 없음"
        DT="NGINX_CONF: not found"
    else
        # root 지시자 확인 (모든 설정 파일에서)
        local ROOT_DIR=$(search_all_configs "^\s*root\s+" | head -1 | awk '{print $2}' | tr -d ';')

        # 기본 경로와 분리 여부 확인
        local DEFAULT_PATHS=("/usr/share/nginx/html" "/var/www/html" "/usr/local/nginx/html")
        local IS_DEFAULT="N"

        for path in "${DEFAULT_PATHS[@]}"; do
            if [ "$ROOT_DIR" = "$path" ]; then
                IS_DEFAULT="Y"
                break
            fi
        done

        if [ -z "$ROOT_DIR" ]; then
            RES="M"
            DESC="root 설정을 찾을 수 없음"
            DT="root: 미설정"
        elif [ "$IS_DEFAULT" = "Y" ]; then
            RES="M"
            DESC="기본 root 경로 사용 중 (수동 확인 필요)"
            DT="root: $ROOT_DIR (기본 경로)"
        else
            RES="Y"
            DESC="별도의 root 경로가 설정됨"
            DT="root: $ROOT_DIR"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check12() {
    local CODE="WEB-12"
    local CAT="서비스관리"
    local NAME="웹 서비스 링크 사용 금지"
    local IMP="중"
    local STD="심볼릭 링크, aliases, 바로가기 등의 링크 사용을 허용하지 않는 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$NGINX_CONF" ] || [ ! -f "$NGINX_CONF" ]; then
        RES="N/A"
        DESC="Nginx 설정 파일을 찾을 수 없음"
        DT="NGINX_CONF: not found"
    else
        # disable_symlinks 설정 확인 (모든 설정 파일에서)
        local DISABLE_SYMLINKS=$(search_all_configs "^\s*disable_symlinks")

        if [ -n "$DISABLE_SYMLINKS" ]; then
            # disable_symlinks on 또는 if_not_owner 설정 확인
            if echo "$DISABLE_SYMLINKS" | grep -qE "(on|if_not_owner)"; then
                RES="Y"
                DESC="심볼릭 링크 사용이 제한되어 있음"
                DT="$DISABLE_SYMLINKS"
            else
                RES="N"
                DESC="심볼릭 링크 사용이 허용되어 있음"
                DT="$DISABLE_SYMLINKS"
            fi
        else
            RES="N"
            DESC="심볼릭 링크 제한 설정이 없음"
            DT="disable_symlinks: 미설정 (기본값: off - 심볼릭 링크 허용)"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check13() {
    local CODE="WEB-13"
    local CAT="서비스관리"
    local NAME="웹 서비스 설정 파일 노출 제한"
    local IMP="상"
    local STD="일반 사용자의 DB 연결 파일에 대한 접근을 제한하고, 불필요한 스크립트 매핑이 제거된 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="WEB-14에서 설정 파일 권한 점검으로 통합"
    local DT="Nginx 설정 파일 노출 제한은 WEB-14(웹 서비스 경로 내 파일의 접근 통제) 항목에서\n설정 파일 권한 점검으로 통합하여 진단합니다.\n해당 점검 항목은 N/A 처리됩니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check14() {
    local CODE="WEB-14"
    local CAT="서비스관리"
    local NAME="웹 서비스 경로 내 파일의 접근 통제"
    local IMP="상"
    local STD="주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여되지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$NGINX_CONF" ] || [ ! -f "$NGINX_CONF" ]; then
        RES="N/A"
        DESC="Nginx 설정 파일을 찾을 수 없음"
        DT="NGINX_CONF: not found"
    else
        # 설정 파일 권한 확인
        local CONF_PERM=$(stat -c "%a" "$NGINX_CONF" 2>/dev/null)
        local CONF_OWNER=$(stat -c "%U:%G" "$NGINX_CONF" 2>/dev/null)

        # other 권한 확인 (마지막 자리)
        local OTHER_PERM=${CONF_PERM: -1}

        if [ "$OTHER_PERM" -eq 0 ]; then
            RES="Y"
            DESC="설정 파일에 적절한 권한이 설정됨"
            DT="$NGINX_CONF\n권한: $CONF_PERM\n소유자: $CONF_OWNER"
        else
            RES="N"
            DESC="설정 파일에 일반 사용자 접근 권한이 있음"
            DT="$NGINX_CONF\n권한: $CONF_PERM (other 권한 제거 필요)\n소유자: $CONF_OWNER"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check15() {
    local CODE="WEB-15"
    local CAT="서비스관리"
    local NAME="웹 서비스의 불필요한 스크립트 매핑 제거"
    local IMP="상"
    local STD="불필요한 스크립트 매핑이 존재하지 않는 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="해당 없음 (Nginx는 location 기반으로 WEB-05에서 점검)"
    local DT="Nginx는 IIS와 같은 스크립트 매핑 방식이 아닌 location 블록 기반으로 스크립트를 처리합니다.\n스크립트 실행 제한은 WEB-05(지정하지 않은 CGI/ISAPI 실행 제한) 항목에서 점검합니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check16() {
    local CODE="WEB-16"
    local CAT="서비스관리"
    local NAME="웹 서비스 헤더 정보 노출 제한"
    local IMP="중"
    local STD="HTTP 응답 헤더에서 웹 서버 정보가 노출되지 않는 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$NGINX_CONF" ] || [ ! -f "$NGINX_CONF" ]; then
        RES="N/A"
        DESC="Nginx 설정 파일을 찾을 수 없음"
        DT="NGINX_CONF: not found"
    else
        # server_tokens 설정 확인 (모든 설정 파일에서)
        local SERVER_TOKENS=$(search_all_configs "^\s*server_tokens" | head -1)

        if [ -n "$SERVER_TOKENS" ]; then
            if echo "$SERVER_TOKENS" | grep -qi "off"; then
                RES="Y"
                DESC="서버 헤더 정보 노출이 제한됨"
                DT="$SERVER_TOKENS"
            else
                RES="N"
                DESC="서버 헤더 정보가 노출될 수 있음"
                DT="$SERVER_TOKENS (off 권장)"
            fi
        else
            RES="N"
            DESC="서버 헤더 정보가 노출될 수 있음"
            DT="server_tokens: 미설정 (기본값: on - 버전 정보 노출)"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check17() {
    local CODE="WEB-17"
    local CAT="서비스관리"
    local NAME="웹 서비스 가상 디렉로리 삭제"
    local IMP="중"
    local STD="불필요한 가상 디렉터리가 존재하지 않는 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$NGINX_CONF" ] || [ ! -f "$NGINX_CONF" ]; then
        RES="N/A"
        DESC="Nginx 설정 파일을 찾을 수 없음"
        DT="NGINX_CONF: not found"
    else
        # alias 설정 확인 (모든 설정 파일에서)
        local ALIASES=$(search_all_configs "^\s*alias\s+")

        if [ -z "$ALIASES" ]; then
            RES="Y"
            DESC="불필요한 alias 설정이 없음"
            DT="alias: 미설정"
        else
            RES="M"
            DESC="alias 설정 존재 (수동 확인 필요)"
            DT="alias 설정:\n$ALIASES"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check18() {
    local CODE="WEB-18"
    local CAT="서비스관리"
    local NAME="웹 서비스 WebDAV 비활성화"
    local IMP="상"
    local STD="WebDAV 서비스를 비활성화하고 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$NGINX_CONF" ] || [ ! -f "$NGINX_CONF" ]; then
        RES="N/A"
        DESC="Nginx 설정 파일을 찾을 수 없음"
        DT="NGINX_CONF: not found"
    else
        # dav_methods 설정 확인 (모든 설정 파일에서)
        local DAV_METHODS=$(search_all_configs "^\s*dav_methods")

        # dav_access 설정 확인
        local DAV_ACCESS=$(search_all_configs "^\s*dav_access")

        # create_full_put_path 설정 확인
        local DAV_PUT_PATH=$(search_all_configs "^\s*create_full_put_path")

        if [ -z "$DAV_METHODS" ] && [ -z "$DAV_ACCESS" ]; then
            RES="Y"
            DESC="WebDAV가 비활성화되어 있음"
            DT="dav_methods: 미설정\ndav_access: 미설정"
        else
            RES="N"
            DESC="WebDAV가 활성화되어 있음"
            local DETAILS=""
            [ -n "$DAV_METHODS" ] && DETAILS="dav_methods:\n$DAV_METHODS\n"
            [ -n "$DAV_ACCESS" ] && DETAILS="${DETAILS}dav_access:\n$DAV_ACCESS\n"
            [ -n "$DAV_PUT_PATH" ] && DETAILS="${DETAILS}create_full_put_path:\n$DAV_PUT_PATH"
            DT="$DETAILS"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check19() {
    local CODE="WEB-19"
    local CAT="보안설정"
    local NAME="웹 서비스 SSI(Server Side Includes) 사용 제한"
    local IMP="중"
    local STD="웹 서비스 SSI 사용 설정이 비활성화되어 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$NGINX_CONF" ] || [ ! -f "$NGINX_CONF" ]; then
        RES="N/A"
        DESC="Nginx 설정 파일을 찾을 수 없음"
        DT="NGINX_CONF: not found"
    else
        # ssi 설정 확인 (모든 설정 파일에서)
        local SSI_ON=$(search_all_configs "^\s*ssi\s+on")

        if [ -z "$SSI_ON" ]; then
            RES="Y"
            DESC="SSI가 비활성화되어 있음"
            DT="ssi: off (기본값) 또는 미설정"
        else
            RES="N"
            DESC="SSI가 활성화되어 있음"
            DT="발견된 설정:\n$SSI_ON"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check20() {
    local CODE="WEB-20"
    local CAT="보안설정"
    local NAME="SSL/TLS 활성화"
    local IMP="상"
    local STD="SSL/TLS 설정이 활성화되어 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$NGINX_CONF" ] || [ ! -f "$NGINX_CONF" ]; then
        RES="N/A"
        DESC="Nginx 설정 파일을 찾을 수 없음"
        DT="NGINX_CONF: not found"
    else
        # ssl_certificate 설정 확인 (모든 설정 파일에서)
        local SSL_CERT=$(search_all_configs "^\s*ssl_certificate\s+" | grep -v "ssl_certificate_key" | head -3)

        # listen 443 ssl 설정 확인
        local LISTEN_SSL=$(search_all_configs "^\s*listen.*443.*ssl" | head -3)

        # ssl_protocols 설정 확인
        local SSL_PROTOCOLS=$(search_all_configs "^\s*ssl_protocols" | head -1)

        if [ -n "$SSL_CERT" ] && [ -n "$LISTEN_SSL" ]; then
            RES="Y"
            DESC="SSL/TLS가 활성화되어 있음"
            DT="ssl_certificate:\n$SSL_CERT\nlisten 443 ssl:\n$LISTEN_SSL\nssl_protocols: ${SSL_PROTOCOLS:-미설정}"
        elif [ -n "$LISTEN_SSL" ]; then
            RES="M"
            DESC="SSL 리스너는 설정되었으나 인증서 설정 확인 필요"
            DT="listen 443 ssl:\n$LISTEN_SSL\nssl_certificate: 수동 확인 필요"
        else
            RES="N"
            DESC="SSL/TLS가 비활성화되어 있음"
            DT="ssl_certificate: 미설정\nlisten 443 ssl: 미설정"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check21() {
    local CODE="WEB-21"
    local CAT="보안설정"
    local NAME="HTTP 리디렉션"
    local IMP="중"
    local STD="HTTP 접근 시 HTTPS Redirection이 활성화된 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$NGINX_CONF" ] || [ ! -f "$NGINX_CONF" ]; then
        RES="N/A"
        DESC="Nginx 설정 파일을 찾을 수 없음"
        DT="NGINX_CONF: not found"
    else
        # return 301 https 설정 확인 (모든 설정 파일에서)
        local REDIRECT_301=$(search_all_configs "^\s*return\s+301\s+https")

        # rewrite https 설정 확인
        local REWRITE_HTTPS=$(search_all_configs "^\s*rewrite.*https")

        # return 302 https 설정도 확인
        local REDIRECT_302=$(search_all_configs "^\s*return\s+302\s+https")

        if [ -n "$REDIRECT_301" ]; then
            RES="Y"
            DESC="HTTP to HTTPS 리디렉션이 설정됨 (301)"
            DT="return 301 https:\n$REDIRECT_301"
        elif [ -n "$REDIRECT_302" ]; then
            RES="Y"
            DESC="HTTP to HTTPS 리디렉션이 설정됨 (302)"
            DT="return 302 https:\n$REDIRECT_302"
        elif [ -n "$REWRITE_HTTPS" ]; then
            RES="Y"
            DESC="HTTP to HTTPS 리디렉션이 설정됨 (rewrite)"
            DT="rewrite https:\n$REWRITE_HTTPS"
        else
            RES="N"
            DESC="HTTP to HTTPS 리디렉션이 설정되지 않음"
            DT="return 301 https: 미설정\nrewrite https: 미설정"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check22() {
    local CODE="WEB-22"
    local CAT="보안설정"
    local NAME="에러 페이지 관리"
    local IMP="하"
    local STD="웹 서비스 에러 페이지가 별도로 지정된 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ -z "$NGINX_CONF" ] || [ ! -f "$NGINX_CONF" ]; then
        RES="N/A"
        DESC="Nginx 설정 파일을 찾을 수 없음"
        DT="NGINX_CONF: not found"
    else
        # error_page 설정 확인 (모든 설정 파일에서)
        local ERROR_PAGE=$(search_all_configs "^\s*error_page")

        if [ -n "$ERROR_PAGE" ]; then
            RES="Y"
            DESC="에러 페이지가 설정되어 있음"
            DT="error_page 설정:\n$ERROR_PAGE"
        else
            RES="N"
            DESC="에러 페이지가 설정되지 않음"
            DT="error_page: 미설정 (기본 에러 페이지 사용)"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check23() {
    local CODE="WEB-23"
    local CAT="보안설정"
    local NAME="LDAP 알고리즘 적절하게 구성"
    local IMP="중"
    local STD="LDAP 연결 인증 시 안전한 비밀번호 다이제스트 알고리즘을 사용하는 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Nginx 자체는 LDAP 인증을 지원하지 않음"
    local DT="Nginx는 자체적으로 LDAP 인증 기능을 지원하지 않습니다.\nLDAP 인증이 필요한 경우 nginx-auth-ldap 모듈을 별도로 설치해야 합니다.\n해당 점검 항목은 N/A 처리됩니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check24() {
    local CODE="WEB-24"
    local CAT="보안설정"
    local NAME="별도의 업로드 경로 사용 및 권한 설정"
    local IMP="중"
    local STD="별도의 업로드 경로를 사용하고 일반 사용자의 접근 권한이 부여되지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

    # 일반적인 업로드 디렉터리 확인
    local UPLOAD_PATHS=(
        "/var/www/html/uploads"
        "/var/www/uploads"
        "/usr/share/nginx/html/uploads"
        "/srv/www/uploads"
    )

    local FOUND_UPLOAD=""
    local UPLOAD_PERMS=""

    for path in "${UPLOAD_PATHS[@]}"; do
        if [ -d "$path" ]; then
            local PERM=$(stat -c "%a" "$path" 2>/dev/null)
            local OWNER=$(stat -c "%U:%G" "$path" 2>/dev/null)
            FOUND_UPLOAD="$path"
            UPLOAD_PERMS="$path - 권한: $PERM, 소유자: $OWNER"
            break
        fi
    done

    if [ -z "$FOUND_UPLOAD" ]; then
        RES="M"
        DESC="업로드 디렉터리를 찾을 수 없음 (수동 확인 필요)"
        DT="일반적인 경로에 업로드 디렉터리 없음"
    else
        local PERM=$(stat -c "%a" "$FOUND_UPLOAD" 2>/dev/null)
        local OTHER_PERM=${PERM: -1}

        if [ "$OTHER_PERM" -eq 0 ]; then
            RES="Y"
            DESC="업로드 디렉터리에 적절한 권한이 설정됨"
            DT="$UPLOAD_PERMS"
        else
            RES="N"
            DESC="업로드 디렉터리에 일반 사용자 접근 권한이 있음"
            DT="$UPLOAD_PERMS (other 권한 제거 필요)"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check25() {
    local CODE="WEB-25"
    local CAT="패치및로그관리"
    local NAME="주기적 보안 패치 및 벤더 권고사항 적용"
    local IMP="상"
    local STD="최신 보안 패치가 적용되어 있으며, 패치 적용 정책을 수립하여 주기적인 패치 관리를 하는 경우"
    local RES=""
    local DESC=""
    local DT=""

    # Nginx 버전 확인
    local VERSION=""
    if command -v nginx &>/dev/null; then
        VERSION=$(nginx -v 2>&1)
    fi

    if [ -z "$VERSION" ]; then
        RES="N/A"
        DESC="Nginx 버전을 확인할 수 없음"
        DT="nginx 명령어를 찾을 수 없음"
    else
        RES="M"
        DESC="버전 정보 확인 (수동 패치 확인 필요)"
        DT="$VERSION\n\n최신 버전 확인: https://nginx.org/en/download.html"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check26() {
    local CODE="WEB-26"
    local CAT="패치및로그관리"
    local NAME="로그 디렉터리 및 파일 권한 설정"
    local IMP="중"
    local STD="로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 없는 경우"
    local RES=""
    local DESC=""
    local DT=""

    # 로그 디렉터리 찾기
    local LOG_DIRS=(
        "/var/log/nginx"
        "/usr/local/nginx/logs"
        "/opt/nginx/logs"
    )

    local FOUND_LOG=""
    for path in "${LOG_DIRS[@]}"; do
        if [ -d "$path" ]; then
            FOUND_LOG="$path"
            break
        fi
    done

    if [ -z "$FOUND_LOG" ]; then
        RES="M"
        DESC="로그 디렉터리를 찾을 수 없음 (수동 확인 필요)"
        DT="일반적인 경로에 로그 디렉터리 없음"
    else
        local DIR_PERM=$(stat -c "%a" "$FOUND_LOG" 2>/dev/null)
        local DIR_OWNER=$(stat -c "%U:%G" "$FOUND_LOG" 2>/dev/null)
        local OTHER_PERM=${DIR_PERM: -1}

        # 로그 파일 권한 확인
        local LOG_FILES=$(find "$FOUND_LOG" -type f -name "*.log" 2>/dev/null | head -3)
        local FILE_PERMS=""
        for f in $LOG_FILES; do
            local F_PERM=$(stat -c "%a %n" "$f" 2>/dev/null)
            FILE_PERMS="$FILE_PERMS\n$F_PERM"
        done

        if [ "$OTHER_PERM" -eq 0 ]; then
            RES="Y"
            DESC="로그 디렉터리에 적절한 권한이 설정됨"
            DT="$FOUND_LOG - 권한: $DIR_PERM, 소유자: $DIR_OWNER\n로그 파일:$FILE_PERMS"
        else
            RES="N"
            DESC="로그 디렉터리에 일반 사용자 접근 권한이 있음"
            DT="$FOUND_LOG - 권한: $DIR_PERM (other 권한 제거 필요)\n소유자: $DIR_OWNER\n로그 파일:$FILE_PERMS"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}


#================================================================
# EXECUTE
#================================================================

echo ""
echo "  $META_PLAT Security Assessment v$META_VER [$META_STD]"
echo "  ─────────────────────────────────────────────────────────"
echo ""
echo "  호스트: $SYS_HOST"
echo "  OS: $SYS_OS_FN"
echo "  서비스: ${SVC_VERSION:-Not found}"
echo "  설정: ${SVC_CONF:-Not found}"
echo ""
echo "  [진단 시작]"
echo "  ─────────────────────────────────────────────────────────"
echo ""

# XML 헤더
cat > "$OUTPUT_FILE" << XMLEOF
<?xml version="1.0" encoding="UTF-8"?>
<seedgen>
    <meta>
        <date>$META_DATE</date>
        <ver>$META_VER</ver>
        <plat>$META_PLAT</plat>
        <type>$META_TYPE</type>
        <std>$META_STD</std>
    </meta>
    <sys>
        <host>$SYS_HOST</host>
        <dom>$SYS_DOM</dom>
        <os>
            <n>$SYS_OS_NAME</n>
            <fn>$SYS_OS_FN</fn>
        </os>
        <kn>$SYS_KN</kn>
        <arch>$SYS_ARCH</arch>
        <net>
            <ip>$SYS_IP</ip>
            <all><![CDATA[$SYS_NET_ALL]]></all>
        </net>
        <svc>
            <ver><![CDATA[${SVC_VERSION:-N/A}]]></ver>
            <conf>${SVC_CONF:-N/A}</conf>
        </svc>
    </sys>
    <results>
XMLEOF

# 진단 실행
    check01
    check02
    check03
    check04
    check05
    check06
    check07
    check08
    check09
    check10
    check11
    check12
    check13
    check14
    check15
    check16
    check17
    check18
    check19
    check20
    check21
    check22
    check23
    check24
    check25
    check26

# XML 종료
cat >> "$OUTPUT_FILE" << XMLEOF
    </results>
</seedgen>
XMLEOF

#================================================================
# CLEANUP
#================================================================
echo ""
echo "  ─────────────────────────────────────────────────────────"
echo ""
echo "  점검이 완료되었습니다!"
echo "  호스트: $SYS_HOST"
echo "  결과 파일: $OUTPUT_FILE"
echo ""
