#!/bin/bash
#================================================================
# JEUS_Linux 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : JEUS_Linux
# 항목  : WEB-01 ~ WEB-26 (26개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

# JEUS 설치 경로 (자동 탐지 실패 시 수동 설정)
JEUS_HOME=""

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="JEUS"
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
# JEUS 설치 경로 자동 탐지
detect_jeus() {
    # JEUS_HOME 환경변수 확인
    if [ -n "$JEUS_HOME" ] && [ -d "$JEUS_HOME" ]; then
        return 0
    fi

    # 환경변수에서 JEUS_HOME 확인
    if [ -n "${JEUS_HOME:-}" ]; then
        if [ -d "$JEUS_HOME" ]; then
            return 0
        fi
    fi

    # 일반적인 JEUS 설치 경로에서 찾기
    local COMMON_PATHS=(
        "/opt/jeus"
        "/opt/jeus8"
        "/opt/jeus7"
        "/home/jeus"
        "/home/jeus8"
        "/home/jeus7"
        "/usr/local/jeus"
        "/usr/local/jeus8"
        "/usr/local/jeus7"
        "/app/jeus"
        "/tmax/jeus"
    )

    for path in "${COMMON_PATHS[@]}"; do
        if [ -d "$path" ]; then
            # JEUS 설치 확인 (bin/jeusadmin 존재 여부)
            if [ -f "$path/bin/jeusadmin" ] || [ -f "$path/bin/startDomainAdminServer" ]; then
                JEUS_HOME="$path"
                return 0
            fi
        fi
    done

    # 프로세스에서 JEUS 경로 추출 시도
    local JEUS_PROC=$(ps aux 2>/dev/null | grep -E "jeus|DomainAdmin" | grep -v grep | head -1)
    if [ -n "$JEUS_PROC" ]; then
        local EXTRACTED_PATH=$(echo "$JEUS_PROC" | grep -oP '(?<=-Djeus\.home=)[^\s]+' | head -1)
        if [ -n "$EXTRACTED_PATH" ] && [ -d "$EXTRACTED_PATH" ]; then
            JEUS_HOME="$EXTRACTED_PATH"
            return 0
        fi
    fi

    # find 명령으로 jeusadmin 찾기 (시간이 오래 걸릴 수 있음)
    local FOUND_JEUS=$(find /opt /home /usr/local /app /tmax -name "jeusadmin" -type f 2>/dev/null | head -1)
    if [ -n "$FOUND_JEUS" ]; then
        JEUS_HOME=$(dirname "$(dirname "$FOUND_JEUS")")
        return 0
    fi
}

# JEUS 탐지 실행
detect_jeus

# JEUS 주요 경로 설정
JEUS_DOMAINS=""
JEUS_CONFIG=""
JEUS_SECURITY=""
ACCOUNTS_XML=""
DOMAIN_XML=""
JEUS_MAIN_XML=""

if [ -n "$JEUS_HOME" ] && [ -d "$JEUS_HOME" ]; then
    # JEUS 7/8 구조
    if [ -d "$JEUS_HOME/domains" ]; then
        JEUS_DOMAINS="$JEUS_HOME/domains"
        # 첫 번째 도메인 찾기
        FIRST_DOMAIN=$(ls -1 "$JEUS_DOMAINS" 2>/dev/null | head -1)
        if [ -n "$FIRST_DOMAIN" ]; then
            JEUS_CONFIG="$JEUS_DOMAINS/$FIRST_DOMAIN/config"
            DOMAIN_XML="$JEUS_CONFIG/domain.xml"
            JEUS_SECURITY="$JEUS_CONFIG/security"
            # 보안 도메인 찾기
            if [ -d "$JEUS_SECURITY" ]; then
                FIRST_SEC_DOMAIN=$(ls -1 "$JEUS_SECURITY" 2>/dev/null | head -1)
                if [ -n "$FIRST_SEC_DOMAIN" ]; then
                    ACCOUNTS_XML="$JEUS_SECURITY/$FIRST_SEC_DOMAIN/accounts.xml"
                fi
            fi
        fi
    fi
    # JEUS 6 구조
    if [ -f "$JEUS_HOME/config/JEUSMain.xml" ]; then
        JEUS_MAIN_XML="$JEUS_HOME/config/JEUSMain.xml"
        JEUS_CONFIG="$JEUS_HOME/config"
    fi
fi

# JEUS 버전 정보
JEUS_VERSION=""
if [ -n "$JEUS_HOME" ] && [ -f "$JEUS_HOME/bin/jeusadmin" ]; then
    JEUS_VERSION=$("$JEUS_HOME/bin/jeusadmin" -version 2>/dev/null | head -1)
fi

SVC_VERSION="$JEUS_VERSION"
SVC_CONF="$JEUS_CONFIG"

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

    if [ -z "$JEUS_HOME" ]; then
        RES="N/A"
        DESC="JEUS 설치 경로를 찾을 수 없음"
        DT="JEUS_HOME: not found"
    elif [ -z "$ACCOUNTS_XML" ] || [ ! -f "$ACCOUNTS_XML" ]; then
        RES="M"
        DESC="accounts.xml 파일을 찾을 수 없음 (수동 확인 필요)"
        DT="accounts.xml: not found\nJEUS_HOME: $JEUS_HOME"
    else
        # 기본 관리자 계정명 확인 (administrator, admin, root 등)
        local DEFAULT_ACCOUNTS=$(grep -iE "<name>(administrator|admin|root|jeus)</name>" "$ACCOUNTS_XML" 2>/dev/null)

        if [ -z "$DEFAULT_ACCOUNTS" ]; then
            RES="Y"
            DESC="기본 관리자 계정명이 변경되어 있음"
            DT="accounts.xml: $ACCOUNTS_XML\n기본 계정(administrator, admin, root, jeus): 미발견"
        else
            RES="N"
            DESC="기본 관리자 계정명이 사용되고 있음"
            DT="accounts.xml: $ACCOUNTS_XML\n발견된 기본 계정:\n$DEFAULT_ACCOUNTS"
        fi
    fi

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

    if [ -z "$JEUS_HOME" ]; then
        RES="N/A"
        DESC="JEUS 설치 경로를 찾을 수 없음"
        DT="JEUS_HOME: not found"
    elif [ -z "$ACCOUNTS_XML" ] || [ ! -f "$ACCOUNTS_XML" ]; then
        RES="M"
        DESC="accounts.xml 파일을 찾을 수 없음 (수동 확인 필요)"
        DT="accounts.xml: not found\nJEUS_HOME: $JEUS_HOME"
    else
        # 비밀번호 암호화 여부 확인
        local PASSWORD_ENTRIES=$(grep -E "<password>" "$ACCOUNTS_XML" 2>/dev/null)

        if [ -z "$PASSWORD_ENTRIES" ]; then
            RES="M"
            DESC="비밀번호 설정을 찾을 수 없음 (수동 확인 필요)"
            DT="accounts.xml: $ACCOUNTS_XML\n<password> 태그: 미발견"
        else
            # 암호화된 비밀번호 확인 (일반적으로 {SHA-256} 등의 접두사가 있음)
            local ENCRYPTED=$(echo "$PASSWORD_ENTRIES" | grep -E "\{(SHA|SHA-256|SHA-512|MD5|PBKDF2)\}" 2>/dev/null)
            local PLAINTEXT=$(echo "$PASSWORD_ENTRIES" | grep -vE "\{(SHA|SHA-256|SHA-512|MD5|PBKDF2)\}" 2>/dev/null | grep -v "^$")

            if [ -n "$PLAINTEXT" ]; then
                RES="N"
                DESC="비밀번호가 암호화되지 않았거나 평문으로 저장됨"
                DT="accounts.xml: $ACCOUNTS_XML\n평문 비밀번호 의심:\n$PLAINTEXT"
            elif [ -n "$ENCRYPTED" ]; then
                RES="Y"
                DESC="비밀번호가 암호화되어 있음"
                DT="accounts.xml: $ACCOUNTS_XML\n암호화 방식 확인됨"
            else
                RES="M"
                DESC="비밀번호 암호화 여부 수동 확인 필요"
                DT="accounts.xml: $ACCOUNTS_XML\n비밀번호 설정:\n$PASSWORD_ENTRIES"
            fi
        fi
    fi

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

    if [ -z "$JEUS_HOME" ]; then
        RES="N/A"
        DESC="JEUS 설치 경로를 찾을 수 없음"
        DT="JEUS_HOME: not found"
    elif [ -z "$ACCOUNTS_XML" ] || [ ! -f "$ACCOUNTS_XML" ]; then
        RES="M"
        DESC="accounts.xml 파일을 찾을 수 없음 (수동 확인 필요)"
        DT="accounts.xml: not found\nJEUS_HOME: $JEUS_HOME"
    else
        local PERM=$(stat -c "%a" "$ACCOUNTS_XML" 2>/dev/null)
        local OWNER=$(stat -c "%U:%G" "$ACCOUNTS_XML" 2>/dev/null)

        # 권한이 600 이하인지 확인
        local GROUP_PERM=${PERM:1:1}
        local OTHER_PERM=${PERM:2:1}

        local DETAILS="accounts.xml: $ACCOUNTS_XML\n권한: $PERM\n소유자: $OWNER"

        # policies.xml 권한도 확인
        local POLICIES_XML=$(dirname "$ACCOUNTS_XML")/policies.xml
        if [ -f "$POLICIES_XML" ]; then
            local POL_PERM=$(stat -c "%a" "$POLICIES_XML" 2>/dev/null)
            local POL_OWNER=$(stat -c "%U:%G" "$POLICIES_XML" 2>/dev/null)
            DETAILS="$DETAILS\n\npolicies.xml: $POLICIES_XML\n권한: $POL_PERM\n소유자: $POL_OWNER"
        fi

        if [ "$GROUP_PERM" -eq 0 ] && [ "$OTHER_PERM" -eq 0 ]; then
            RES="Y"
            DESC="비밀번호 파일에 적절한 권한(600 이하)이 설정됨"
            DT="$DETAILS"
        else
            RES="N"
            DESC="비밀번호 파일 권한이 600 초과로 설정됨"
            DT="$DETAILS\n\n권장: chmod 600"
        fi
    fi

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

    if [ -z "$JEUS_HOME" ]; then
        RES="N/A"
        DESC="JEUS 설치 경로를 찾을 수 없음"
        DT="JEUS_HOME: not found"
    else
        # jeus-web-dd.xml 파일 찾기
        local JEUS_WEB_DD_FILES=$(find "$JEUS_HOME" -name "jeus-web-dd.xml" -type f 2>/dev/null)

        if [ -z "$JEUS_WEB_DD_FILES" ]; then
            RES="M"
            DESC="jeus-web-dd.xml 파일을 찾을 수 없음 (수동 확인 필요)"
            DT="JEUS_HOME: $JEUS_HOME\njeus-web-dd.xml: not found"
        else
            local INDEXING_ENABLED=""
            local CHECKED_FILES=""

            while IFS= read -r file; do
                CHECKED_FILES="$CHECKED_FILES\n$file"
                # allow-indexing 설정 확인
                local INDEXING=$(grep -i "<allow-indexing>" "$file" 2>/dev/null)
                if echo "$INDEXING" | grep -qi "true"; then
                    INDEXING_ENABLED="$INDEXING_ENABLED\n$file: $INDEXING"
                fi
            done <<< "$JEUS_WEB_DD_FILES"

            if [ -z "$INDEXING_ENABLED" ]; then
                RES="Y"
                DESC="디렉터리 리스팅이 비활성화되어 있음"
                DT="점검 파일:$CHECKED_FILES\n\nallow-indexing: false 또는 미설정"
            else
                RES="N"
                DESC="디렉터리 리스팅이 활성화되어 있음"
                DT="점검 파일:$CHECKED_FILES\n\n취약 설정 발견:$INDEXING_ENABLED"
            fi
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

    local RES="N/A"
    local DESC="JEUS는 WAS로서 CGI/ISAPI를 지원하지 않음 (서블릿 기반)"
    local DT="JEUS는 Java EE 기반 WAS로서 CGI/ISAPI 방식을 지원하지 않습니다.\n서블릿/JSP 기반으로 동작하므로 해당 항목은 적용 대상이 아닙니다."

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

    local RES="N/A"
    local DESC="JEUS는 WAS로서 상위 디렉터리 접근이 웹 컨텍스트로 제한됨"
    local DT="JEUS는 Java EE 기반 WAS로서 웹 애플리케이션 컨텍스트 내에서만 리소스 접근이 가능합니다.\n상위 디렉터리(../) 접근은 서블릿 컨테이너에 의해 기본적으로 제한됩니다."

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

    if [ -z "$JEUS_HOME" ]; then
        RES="N/A"
        DESC="JEUS 설치 경로를 찾을 수 없음"
        DT="JEUS_HOME: not found"
    else
        local FOUND_UNNECESSARY=""

        # docs/manuals 디렉터리 확인
        if [ -d "$JEUS_HOME/docs/manuals" ]; then
            local MANUAL_FILES=$(find "$JEUS_HOME/docs/manuals" -type f 2>/dev/null | head -5)
            if [ -n "$MANUAL_FILES" ]; then
                FOUND_UNNECESSARY="$FOUND_UNNECESSARY\n매뉴얼 디렉터리:\n$MANUAL_FILES"
            fi
        fi

        # samples 디렉터리 확인
        if [ -d "$JEUS_HOME/samples" ]; then
            local SAMPLE_FILES=$(find "$JEUS_HOME/samples" -type f 2>/dev/null | head -5)
            if [ -n "$SAMPLE_FILES" ]; then
                FOUND_UNNECESSARY="$FOUND_UNNECESSARY\n샘플 디렉터리:\n$SAMPLE_FILES"
            fi
        fi

        # 불필요한 파일 패턴 확인 (*.bak, *.backup, *.old, *.tmp 등)
        local BACKUP_FILES=$(find "$JEUS_HOME" -type f \( -name "*.bak" -o -name "*.backup" -o -name "*.old" -o -name "*.tmp" -o -name "*.swp" \) 2>/dev/null | head -10)
        if [ -n "$BACKUP_FILES" ]; then
            FOUND_UNNECESSARY="$FOUND_UNNECESSARY\n백업/임시 파일:\n$BACKUP_FILES"
        fi

        if [ -z "$FOUND_UNNECESSARY" ]; then
            RES="Y"
            DESC="불필요한 파일 및 디렉터리가 없음"
            DT="JEUS_HOME: $JEUS_HOME\n매뉴얼/샘플/백업 파일: 미발견"
        else
            RES="N"
            DESC="불필요한 파일 또는 디렉터리가 존재함"
            DT="JEUS_HOME: $JEUS_HOME$FOUND_UNNECESSARY"
        fi
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

    if [ -z "$JEUS_HOME" ]; then
        RES="N/A"
        DESC="JEUS 설치 경로를 찾을 수 없음"
        DT="JEUS_HOME: not found"
    else
        # web.xml 파일 찾기
        local WEB_XML_FILES=$(find "$JEUS_HOME" -name "web.xml" -type f 2>/dev/null | head -10)

        if [ -z "$WEB_XML_FILES" ]; then
            RES="M"
            DESC="web.xml 파일을 찾을 수 없음 (수동 확인 필요)"
            DT="JEUS_HOME: $JEUS_HOME\nweb.xml: not found"
        else
            local SIZE_LIMIT_FOUND=""
            local CHECKED_FILES=""

            while IFS= read -r file; do
                CHECKED_FILES="$CHECKED_FILES\n$file"
                # max-file-size 또는 multipart-config 설정 확인
                local SIZE_CONFIG=$(grep -iE "<max-file-size>|<max-request-size>|<multipart-config>" "$file" 2>/dev/null)
                if [ -n "$SIZE_CONFIG" ]; then
                    SIZE_LIMIT_FOUND="$SIZE_LIMIT_FOUND\n$file:\n$SIZE_CONFIG"
                fi
            done <<< "$WEB_XML_FILES"

            if [ -n "$SIZE_LIMIT_FOUND" ]; then
                RES="Y"
                DESC="파일 업로드 용량 제한이 설정됨"
                DT="점검 파일:$CHECKED_FILES\n\n용량 제한 설정:$SIZE_LIMIT_FOUND"
            else
                RES="N"
                DESC="파일 업로드 용량 제한이 설정되지 않음"
                DT="점검 파일:$CHECKED_FILES\n\nmax-file-size/multipart-config: 미설정"
            fi
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

    # JEUS 프로세스 실행 계정 확인
    local JEUS_PROC=$(ps aux 2>/dev/null | grep -E "jeus|DomainAdmin|nodemanager" | grep -v grep)
    local JEUS_USER=$(echo "$JEUS_PROC" | awk '{print $1}' | sort -u | head -1)

    if [ -z "$JEUS_PROC" ]; then
        RES="M"
        DESC="JEUS 프로세스가 실행 중이지 않음 (수동 확인 필요)"
        DT="JEUS 프로세스: 미발견"
    elif [ "$JEUS_USER" = "root" ]; then
        RES="N"
        DESC="JEUS가 root 권한으로 실행 중"
        DT="실행 계정: $JEUS_USER\n\n프로세스 정보:\n$JEUS_PROC"
    else
        RES="Y"
        DESC="JEUS가 제한된 권한으로 실행 중"
        DT="실행 계정: $JEUS_USER\n\n프로세스 정보:\n$JEUS_PROC"
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

    if [ -z "$JEUS_HOME" ]; then
        RES="N/A"
        DESC="JEUS 설치 경로를 찾을 수 없음"
        DT="JEUS_HOME: not found"
    else
        # ReverseProxy 관련 web.xml 찾기
        local PROXY_CONFIG=$(find "$JEUS_HOME" -path "*ReverseProxy*" -name "web.xml" -type f 2>/dev/null)
        local PROXY_SETTINGS=""

        # domain.xml에서 프록시 설정 확인
        if [ -f "$DOMAIN_XML" ]; then
            local DOMAIN_PROXY=$(grep -iE "<proxy|<reverse-proxy" "$DOMAIN_XML" 2>/dev/null)
            if [ -n "$DOMAIN_PROXY" ]; then
                PROXY_SETTINGS="domain.xml 프록시 설정:\n$DOMAIN_PROXY"
            fi
        fi

        # web.xml에서 프록시 설정 확인
        if [ -n "$PROXY_CONFIG" ]; then
            PROXY_SETTINGS="$PROXY_SETTINGS\n\nReverseProxy web.xml:\n$PROXY_CONFIG"
        fi

        if [ -z "$PROXY_SETTINGS" ]; then
            RES="Y"
            DESC="프록시 설정이 비활성화되어 있음"
            DT="JEUS_HOME: $JEUS_HOME\n프록시 설정: 미발견"
        else
            RES="M"
            DESC="프록시 설정 존재 (수동 확인 필요)"
            DT="JEUS_HOME: $JEUS_HOME\n\n$PROXY_SETTINGS"
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

    if [ -z "$JEUS_HOME" ]; then
        RES="N/A"
        DESC="JEUS 설치 경로를 찾을 수 없음"
        DT="JEUS_HOME: not found"
    else
        # ws_engine.m 또는 domain.xml에서 Docroot 확인
        local DOCROOT_SETTINGS=""

        # domain.xml 확인
        if [ -f "$DOMAIN_XML" ]; then
            local DOCROOT=$(grep -iE "<doc-root>|<docroot>|<document-root>" "$DOMAIN_XML" 2>/dev/null)
            if [ -n "$DOCROOT" ]; then
                DOCROOT_SETTINGS="domain.xml:\n$DOCROOT"
            fi
        fi

        # ws_engine.m 파일 확인
        local WS_ENGINE=$(find "$JEUS_HOME" -name "ws_engine.m" -type f 2>/dev/null)
        if [ -n "$WS_ENGINE" ]; then
            while IFS= read -r file; do
                local ENGINE_DOCROOT=$(grep -i "Docroot" "$file" 2>/dev/null)
                if [ -n "$ENGINE_DOCROOT" ]; then
                    DOCROOT_SETTINGS="$DOCROOT_SETTINGS\n\nws_engine.m ($file):\n$ENGINE_DOCROOT"
                fi
            done <<< "$WS_ENGINE"
        fi

        if [ -z "$DOCROOT_SETTINGS" ]; then
            RES="M"
            DESC="DocumentRoot 설정을 찾을 수 없음 (수동 확인 필요)"
            DT="JEUS_HOME: $JEUS_HOME\nDocroot 설정: 미발견"
        else
            RES="M"
            DESC="DocumentRoot 설정 확인 필요"
            DT="JEUS_HOME: $JEUS_HOME\n\n$DOCROOT_SETTINGS"
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

    if [ -z "$JEUS_HOME" ]; then
        RES="N/A"
        DESC="JEUS 설치 경로를 찾을 수 없음"
        DT="JEUS_HOME: not found"
    else
        # jeus-web-dd.xml에서 alias 설정 확인
        local JEUS_WEB_DD_FILES=$(find "$JEUS_HOME" -name "jeus-web-dd.xml" -type f 2>/dev/null)
        local ALIAS_FOUND=""

        if [ -n "$JEUS_WEB_DD_FILES" ]; then
            while IFS= read -r file; do
                local ALIAS_CONFIG=$(grep -iE "<aliasing>|<alias>|<alias-name>|<real-path>" "$file" 2>/dev/null)
                if [ -n "$ALIAS_CONFIG" ]; then
                    ALIAS_FOUND="$ALIAS_FOUND\n$file:\n$ALIAS_CONFIG"
                fi
            done <<< "$JEUS_WEB_DD_FILES"
        fi

        if [ -z "$ALIAS_FOUND" ]; then
            RES="Y"
            DESC="심볼릭 링크/별칭 설정이 없음"
            DT="JEUS_HOME: $JEUS_HOME\naliasing 설정: 미발견"
        else
            RES="M"
            DESC="별칭(aliasing) 설정 존재 (수동 확인 필요)"
            DT="JEUS_HOME: $JEUS_HOME\n\n발견된 aliasing 설정:$ALIAS_FOUND"
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

    if [ -z "$JEUS_HOME" ]; then
        RES="N/A"
        DESC="JEUS 설치 경로를 찾을 수 없음"
        DT="JEUS_HOME: not found"
    else
        local CONFIG_FILES=""
        local VULNERABLE=""

        # domain.xml 권한 확인
        if [ -f "$DOMAIN_XML" ]; then
            local PERM=$(stat -c "%a" "$DOMAIN_XML" 2>/dev/null)
            local OTHER_PERM=${PERM:2:1}
            CONFIG_FILES="$CONFIG_FILES\ndomain.xml: $DOMAIN_XML (권한: $PERM)"
            if [ "$OTHER_PERM" -gt 0 ]; then
                VULNERABLE="$VULNERABLE\ndomain.xml: $DOMAIN_XML (권한: $PERM, other 접근 가능)"
            fi
        fi

        # JEUSMain.xml 권한 확인 (JEUS 6)
        if [ -f "$JEUS_MAIN_XML" ]; then
            local PERM=$(stat -c "%a" "$JEUS_MAIN_XML" 2>/dev/null)
            local OTHER_PERM=${PERM:2:1}
            CONFIG_FILES="$CONFIG_FILES\nJEUSMain.xml: $JEUS_MAIN_XML (권한: $PERM)"
            if [ "$OTHER_PERM" -gt 0 ]; then
                VULNERABLE="$VULNERABLE\nJEUSMain.xml: $JEUS_MAIN_XML (권한: $PERM, other 접근 가능)"
            fi
        fi

        # jeus-web-dd.xml 파일 권한 확인
        local JEUS_WEB_DD=$(find "$JEUS_HOME" -name "jeus-web-dd.xml" -type f 2>/dev/null | head -5)
        if [ -n "$JEUS_WEB_DD" ]; then
            while IFS= read -r file; do
                local PERM=$(stat -c "%a" "$file" 2>/dev/null)
                local OTHER_PERM=${PERM:2:1}
                CONFIG_FILES="$CONFIG_FILES\njeus-web-dd.xml: $file (권한: $PERM)"
                if [ "$OTHER_PERM" -gt 0 ]; then
                    VULNERABLE="$VULNERABLE\njeus-web-dd.xml: $file (권한: $PERM, other 접근 가능)"
                fi
            done <<< "$JEUS_WEB_DD"
        fi

        if [ -z "$CONFIG_FILES" ]; then
            RES="M"
            DESC="설정 파일을 찾을 수 없음 (수동 확인 필요)"
            DT="JEUS_HOME: $JEUS_HOME\n설정 파일: 미발견"
        elif [ -n "$VULNERABLE" ]; then
            RES="N"
            DESC="설정 파일에 일반 사용자 접근 권한이 있음"
            DT="JEUS_HOME: $JEUS_HOME\n\n취약 설정 파일:$VULNERABLE\n\n권장: chmod 600"
        else
            RES="Y"
            DESC="설정 파일에 적절한 권한이 설정됨"
            DT="JEUS_HOME: $JEUS_HOME\n\n점검 파일:$CONFIG_FILES"
        fi
    fi

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

    if [ -z "$JEUS_HOME" ]; then
        RES="N/A"
        DESC="JEUS 설치 경로를 찾을 수 없음"
        DT="JEUS_HOME: not found"
    elif [ -z "$ACCOUNTS_XML" ] || [ ! -f "$ACCOUNTS_XML" ]; then
        RES="M"
        DESC="accounts.xml 파일을 찾을 수 없음 (수동 확인 필요)"
        DT="accounts.xml: not found\nJEUS_HOME: $JEUS_HOME"
    else
        local PERM=$(stat -c "%a" "$ACCOUNTS_XML" 2>/dev/null)
        local OWNER=$(stat -c "%U:%G" "$ACCOUNTS_XML" 2>/dev/null)
        local OTHER_PERM=${PERM:2:1}

        local DETAILS="accounts.xml: $ACCOUNTS_XML\n권한: $PERM\n소유자: $OWNER"

        # 750 이하인지 확인
        if [ "$OTHER_PERM" -eq 0 ]; then
            RES="Y"
            DESC="주요 설정 파일에 적절한 권한이 설정됨"
            DT="$DETAILS"
        else
            RES="N"
            DESC="주요 설정 파일에 불필요한 접근 권한이 부여됨"
            DT="$DETAILS\n\n권장: chmod 750 또는 chmod 600"
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

    if [ -z "$JEUS_HOME" ]; then
        RES="N/A"
        DESC="JEUS 설치 경로를 찾을 수 없음"
        DT="JEUS_HOME: not found"
    else
        # web.xml에서 servlet-mapping 확인
        local WEB_XML_FILES=$(find "$JEUS_HOME" -name "web.xml" -type f 2>/dev/null | head -10)
        local SERVLET_MAPPINGS=""

        if [ -z "$WEB_XML_FILES" ]; then
            RES="M"
            DESC="web.xml 파일을 찾을 수 없음 (수동 확인 필요)"
            DT="JEUS_HOME: $JEUS_HOME\nweb.xml: not found"
        else
            while IFS= read -r file; do
                # servlet-mapping 설정 확인
                local MAPPINGS=$(grep -A5 "<servlet-mapping>" "$file" 2>/dev/null | grep -E "<url-pattern>|<servlet-name>")
                if [ -n "$MAPPINGS" ]; then
                    SERVLET_MAPPINGS="$SERVLET_MAPPINGS\n$file:\n$MAPPINGS"
                fi
            done <<< "$WEB_XML_FILES"

            if [ -z "$SERVLET_MAPPINGS" ]; then
                RES="Y"
                DESC="불필요한 스크립트 매핑이 없음"
                DT="JEUS_HOME: $JEUS_HOME\nservlet-mapping: 미발견"
            else
                RES="M"
                DESC="스크립트 매핑 존재 (수동 확인 필요)"
                DT="JEUS_HOME: $JEUS_HOME\n\n발견된 servlet-mapping:$SERVLET_MAPPINGS"
            fi
        fi
    fi

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

    if [ -z "$JEUS_HOME" ]; then
        RES="N/A"
        DESC="JEUS 설치 경로를 찾을 수 없음"
        DT="JEUS_HOME: not found"
    else
        local HEADER_CONFIG=""
        local IS_CONFIGURED="N"

        # JEUS 7 이상: domain.xml에서 response-header 확인
        if [ -f "$DOMAIN_XML" ]; then
            local RESPONSE_HEADER=$(grep -iE "<response-header>|<custom-header>|serverInfo" "$DOMAIN_XML" 2>/dev/null)
            if [ -n "$RESPONSE_HEADER" ]; then
                HEADER_CONFIG="domain.xml:\n$RESPONSE_HEADER"
                IS_CONFIGURED="Y"
            fi
        fi

        # JEUS 6: JEUSMain.xml에서 serverInfo 확인
        if [ -f "$JEUS_MAIN_XML" ]; then
            local SERVER_INFO=$(grep -i "serverInfo" "$JEUS_MAIN_XML" 2>/dev/null)
            if [ -n "$SERVER_INFO" ]; then
                HEADER_CONFIG="$HEADER_CONFIG\n\nJEUSMain.xml:\n$SERVER_INFO"
                IS_CONFIGURED="Y"
            fi
        fi

        # command-option에서 -Djeus.servlet.response.header.serverInfo=false 확인
        local CMD_OPTION=$(grep -rE "Djeus.servlet.response.header.serverInfo" "$JEUS_HOME" --include="*.xml" 2>/dev/null)
        if [ -n "$CMD_OPTION" ]; then
            HEADER_CONFIG="$HEADER_CONFIG\n\ncommand-option:\n$CMD_OPTION"
            if echo "$CMD_OPTION" | grep -q "false"; then
                IS_CONFIGURED="Y"
            fi
        fi

        if [ "$IS_CONFIGURED" = "Y" ]; then
            RES="Y"
            DESC="서버 헤더 정보 노출이 제한됨"
            DT="JEUS_HOME: $JEUS_HOME\n\n$HEADER_CONFIG"
        else
            RES="N"
            DESC="서버 헤더 정보가 노출될 수 있음"
            DT="JEUS_HOME: $JEUS_HOME\n\nserverInfo 설정: 미발견\n\n권장: domain.xml 또는 JEUSMain.xml에 serverInfo=false 설정"
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

    local RES="N/A"
    local DESC="JEUS는 WAS로서 가상 디렉터리 개념이 없음 (웹 애플리케이션 배포 방식)"
    local DT="JEUS는 웹 서버가 아닌 WAS로서 가상 디렉터리 개념을 사용하지 않습니다.\n웹 애플리케이션은 WAR/EAR 형태로 배포되며 컨텍스트 경로로 접근합니다."

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

    local RES="N/A"
    local DESC="JEUS는 기본적으로 WebDAV를 지원하지 않음"
    local DT="JEUS는 기본 설치 시 WebDAV 기능을 제공하지 않습니다.\n별도의 WebDAV 서블릿을 배포하지 않는 한 해당 기능은 사용되지 않습니다."

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

    local RES="N/A"
    local DESC="JEUS는 WAS로서 SSI를 지원하지 않음 (JSP/서블릿 기반)"
    local DT="JEUS는 Java EE 기반 WAS로서 Server Side Includes(SSI)를 지원하지 않습니다.\n동적 콘텐츠 처리는 JSP, 서블릿을 통해 수행됩니다."

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

    local RES="N/A"
    local DESC="JEUS 앞단에 웹서버를 두고 SSL 처리 권장"
    local DT="JEUS WAS 단독으로 SSL/TLS를 처리하는 것보다 앞단 웹서버(Apache, WebtoB 등)에서\nSSL Offloading을 수행하는 아키텍처를 권장합니다.\n앞단 웹서버의 SSL/TLS 설정을 점검하시기 바랍니다."

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

    local RES="N/A"
    local DESC="JEUS 앞단 웹서버에서 HTTPS 리디렉션 처리 권장"
    local DT="HTTP에서 HTTPS로의 리디렉션은 앞단 웹서버(Apache, WebtoB 등)에서\n처리하는 것이 권장됩니다.\n앞단 웹서버의 리디렉션 설정을 점검하시기 바랍니다."

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

    if [ -z "$JEUS_HOME" ]; then
        RES="N/A"
        DESC="JEUS 설치 경로를 찾을 수 없음"
        DT="JEUS_HOME: not found"
    else
        # web.xml에서 error-page 설정 확인
        local WEB_XML_FILES=$(find "$JEUS_HOME" -name "web.xml" -o -name "webcommon.xml" -type f 2>/dev/null | head -10)
        local ERROR_PAGE_FOUND=""

        if [ -z "$WEB_XML_FILES" ]; then
            RES="M"
            DESC="web.xml 파일을 찾을 수 없음 (수동 확인 필요)"
            DT="JEUS_HOME: $JEUS_HOME\nweb.xml: not found"
        else
            while IFS= read -r file; do
                local ERROR_PAGES=$(grep -A3 "<error-page>" "$file" 2>/dev/null | grep -E "<error-code>|<location>")
                if [ -n "$ERROR_PAGES" ]; then
                    ERROR_PAGE_FOUND="$ERROR_PAGE_FOUND\n$file:\n$ERROR_PAGES"
                fi
            done <<< "$WEB_XML_FILES"

            if [ -n "$ERROR_PAGE_FOUND" ]; then
                RES="Y"
                DESC="에러 페이지가 설정되어 있음"
                DT="JEUS_HOME: $JEUS_HOME\n\n에러 페이지 설정:$ERROR_PAGE_FOUND"
            else
                RES="N"
                DESC="에러 페이지가 설정되지 않음"
                DT="JEUS_HOME: $JEUS_HOME\nerror-page: 미설정 (기본 에러 페이지 사용)"
            fi
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
    local DESC="JEUS LDAP 연동은 별도 보안 모듈 설정으로 관리"
    local DT="JEUS에서 LDAP 연동 시 보안 설정은 별도의 Security Domain 설정을 통해 관리됩니다.\nLDAP 연동을 사용하는 경우 domain.xml 또는 security 설정의 LDAP 관련 항목을 점검하시기 바랍니다."

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

    if [ -z "$JEUS_HOME" ]; then
        RES="N/A"
        DESC="JEUS 설치 경로를 찾을 수 없음"
        DT="JEUS_HOME: not found"
    else
        # web.xml에서 uploadDir 설정 확인
        local WEB_XML_FILES=$(find "$JEUS_HOME" -name "web.xml" -type f 2>/dev/null | head -10)
        local UPLOAD_CONFIG=""

        if [ -n "$WEB_XML_FILES" ]; then
            while IFS= read -r file; do
                local UPLOAD_DIR=$(grep -iE "<param-name>uploadDir</param-name>|<param-value>.*upload.*</param-value>" "$file" 2>/dev/null)
                if [ -n "$UPLOAD_DIR" ]; then
                    UPLOAD_CONFIG="$UPLOAD_CONFIG\n$file:\n$UPLOAD_DIR"
                fi
            done <<< "$WEB_XML_FILES"
        fi

        # 일반적인 업로드 디렉터리 경로 확인
        local UPLOAD_PATHS=(
            "$JEUS_HOME/domains/*/servers/*/apps/*/upload"
            "$JEUS_HOME/upload"
            "/var/www/upload"
            "/home/*/upload"
        )

        local FOUND_UPLOAD=""
        for pattern in "${UPLOAD_PATHS[@]}"; do
            for path in $pattern; do
                if [ -d "$path" ]; then
                    local PERM=$(stat -c "%a" "$path" 2>/dev/null)
                    local OWNER=$(stat -c "%U:%G" "$path" 2>/dev/null)
                    FOUND_UPLOAD="$FOUND_UPLOAD\n$path - 권한: $PERM, 소유자: $OWNER"
                fi
            done
        done

        if [ -z "$UPLOAD_CONFIG" ] && [ -z "$FOUND_UPLOAD" ]; then
            RES="M"
            DESC="업로드 디렉터리 설정을 찾을 수 없음 (수동 확인 필요)"
            DT="JEUS_HOME: $JEUS_HOME\nuploadDir: 미발견"
        else
            RES="M"
            DESC="업로드 경로 설정 확인 필요"
            local DETAILS="JEUS_HOME: $JEUS_HOME"
            [ -n "$UPLOAD_CONFIG" ] && DETAILS="$DETAILS\n\n설정 파일:$UPLOAD_CONFIG"
            [ -n "$FOUND_UPLOAD" ] && DETAILS="$DETAILS\n\n발견된 업로드 디렉터리:$FOUND_UPLOAD"
            DT="$DETAILS"
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

    if [ -z "$JEUS_HOME" ]; then
        RES="N/A"
        DESC="JEUS 설치 경로를 찾을 수 없음"
        DT="JEUS_HOME: not found"
    else
        local VERSION=""

        # jeusadmin -version으로 버전 확인
        if [ -f "$JEUS_HOME/bin/jeusadmin" ]; then
            VERSION=$("$JEUS_HOME/bin/jeusadmin" -version 2>/dev/null | head -3)
            if [ -z "$VERSION" ]; then
                VERSION=$("$JEUS_HOME/bin/jeusadmin" -fullversion 2>/dev/null | head -3)
            fi
        fi

        # JEUS 프로퍼티 파일에서 버전 확인
        if [ -z "$VERSION" ]; then
            local VERSION_FILE=$(find "$JEUS_HOME" -name "jeus.properties" -o -name "version.txt" -type f 2>/dev/null | head -1)
            if [ -n "$VERSION_FILE" ]; then
                VERSION=$(cat "$VERSION_FILE" 2>/dev/null | head -5)
            fi
        fi

        if [ -z "$VERSION" ]; then
            RES="M"
            DESC="JEUS 버전을 확인할 수 없음 (수동 확인 필요)"
            DT="JEUS_HOME: $JEUS_HOME\njeusadmin -version: 실행 불가"
        else
            RES="M"
            DESC="버전 정보 확인 (수동 패치 확인 필요)"
            DT="JEUS_HOME: $JEUS_HOME\n\n버전 정보:\n$VERSION\n\n최신 버전 확인: https://technet.tmaxsoft.com/ko/front/download/findDownloadList.do"
        fi
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

    if [ -z "$JEUS_HOME" ]; then
        RES="N/A"
        DESC="JEUS 설치 경로를 찾을 수 없음"
        DT="JEUS_HOME: not found"
    else
        # JEUS 로그 디렉터리 찾기
        local LOG_DIRS=$(find "$JEUS_HOME" -type d -name "logs" 2>/dev/null | head -5)

        if [ -z "$LOG_DIRS" ]; then
            RES="M"
            DESC="로그 디렉터리를 찾을 수 없음 (수동 확인 필요)"
            DT="JEUS_HOME: $JEUS_HOME\nlogs: not found"
        else
            local VULNERABLE=""
            local LOG_INFO=""

            while IFS= read -r log_dir; do
                local DIR_PERM=$(stat -c "%a" "$log_dir" 2>/dev/null)
                local DIR_OWNER=$(stat -c "%U:%G" "$log_dir" 2>/dev/null)
                local OTHER_PERM=${DIR_PERM:2:1}

                LOG_INFO="$LOG_INFO\n$log_dir - 권한: $DIR_PERM, 소유자: $DIR_OWNER"

                if [ "$OTHER_PERM" -gt 0 ]; then
                    VULNERABLE="$VULNERABLE\n$log_dir (권한: $DIR_PERM, other 접근 가능)"
                fi

                # 로그 파일 권한 확인
                local LOG_FILES=$(find "$log_dir" -type f -name "*.log" 2>/dev/null | head -3)
                if [ -n "$LOG_FILES" ]; then
                    while IFS= read -r log_file; do
                        local FILE_PERM=$(stat -c "%a" "$log_file" 2>/dev/null)
                        local FILE_OTHER=${FILE_PERM:2:1}
                        LOG_INFO="$LOG_INFO\n  - $(basename "$log_file"): $FILE_PERM"
                        if [ "$FILE_OTHER" -gt 0 ]; then
                            VULNERABLE="$VULNERABLE\n$log_file (권한: $FILE_PERM)"
                        fi
                    done <<< "$LOG_FILES"
                fi
            done <<< "$LOG_DIRS"

            if [ -n "$VULNERABLE" ]; then
                RES="N"
                DESC="로그 디렉터리 및 파일에 일반 사용자 접근 권한이 있음"
                DT="JEUS_HOME: $JEUS_HOME\n\n취약 항목:$VULNERABLE\n\n권장: 디렉터리 750, 파일 640"
            else
                RES="Y"
                DESC="로그 디렉터리 및 파일에 적절한 권한이 설정됨"
                DT="JEUS_HOME: $JEUS_HOME\n\n로그 정보:$LOG_INFO"
            fi
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
