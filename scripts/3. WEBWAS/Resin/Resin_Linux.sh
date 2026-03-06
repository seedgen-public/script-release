#!/bin/bash
#================================================================
# Resin_Linux 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : Resin_Linux
# 항목  : WEB-01 ~ WEB-26 (26개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

# Resin 설치 경로 (자동 탐지 실패 시 수동 설정)
RESIN_HOME=""
RESIN_CONF=""

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="Resin"
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
# DETECT — Resin 설치 경로 탐지
#================================================================
detect_resin() {
    # 1. 환경변수 확인
    if [ -n "$RESIN_HOME" ] && [ -d "$RESIN_HOME" ]; then
        RESIN_CONF="$RESIN_HOME/conf"
        return
    fi

    # 2. 일반적인 설치 경로 확인
    local COMMON_PATHS=(
        "/usr/local/resin"
        "/opt/resin"
        "/opt/caucho/resin"
    )

    for path in "${COMMON_PATHS[@]}"; do
        if [ -d "$path" ] && [ -f "$path/conf/resin.xml" ]; then
            RESIN_HOME="$path"
            RESIN_CONF="$path/conf"
            return
        fi
    done

    # 와일드카드 경로 탐색
    for path in /usr/local/resin-* /opt/resin-*; do
        if [ -d "$path" ] && [ -f "$path/conf/resin.xml" ]; then
            RESIN_HOME="$path"
            RESIN_CONF="$path/conf"
            return
        fi
    done

    # 3. 프로세스에서 resin.home 추출
    local PROC_HOME
    PROC_HOME=$(ps aux 2>/dev/null | grep "resin" | grep -v grep | head -1 | sed -n 's/.*-Dresin.home=\([^ ]*\).*/\1/p')
    if [ -n "$PROC_HOME" ] && [ -d "$PROC_HOME" ]; then
        RESIN_HOME="$PROC_HOME"
        RESIN_CONF="$PROC_HOME/conf"
        return
    fi

    # 4. systemd에서 RESIN_HOME 추출
    local SYSTEMD_HOME
    SYSTEMD_HOME=$(systemctl cat resin 2>/dev/null | grep "RESIN_HOME" | cut -d'=' -f2 | tr -d '"' | head -1)
    if [ -n "$SYSTEMD_HOME" ] && [ -d "$SYSTEMD_HOME" ]; then
        RESIN_HOME="$SYSTEMD_HOME"
        RESIN_CONF="$SYSTEMD_HOME/conf"
        return
    fi
}

# Resin 탐지 실행
detect_resin

# 탐지 실패 시 종료
if [ -z "$RESIN_HOME" ] || [ ! -d "$RESIN_HOME" ]; then
    echo "[!] Resin 설치 경로를 찾을 수 없습니다."
    echo "    RESIN_HOME 환경변수를 설정하거나, 스크립트 상단에서 직접 지정하세요."
    exit 1
fi

# Resin 버전 정보
RESIN_VERSION=""
if [ -f "${RESIN_HOME}/lib/resin.jar" ]; then
    RESIN_VERSION=$(java -jar "${RESIN_HOME}/lib/resin.jar" version 2>/dev/null | head -1)
    if [ -z "$RESIN_VERSION" ]; then
        RESIN_VERSION=$(unzip -p "${RESIN_HOME}/lib/resin.jar" META-INF/MANIFEST.MF 2>/dev/null | grep -i "Implementation-Version" | cut -d':' -f2 | tr -d ' \r')
    fi
fi

# 주요 설정 파일 경로
RESIN_XML="${RESIN_CONF}/resin.xml"
RESIN_PROPERTIES="${RESIN_CONF}/resin.properties"
ADMIN_USERS_XML="${RESIN_CONF}/admin-users.xml"
WEB_XML="${RESIN_CONF}/web.xml"
WEBAPPS_DIR="${RESIN_HOME}/webapps"
LOG_DIR="${RESIN_HOME}/log"

SVC_VERSION="$RESIN_VERSION"
SVC_CONF="$RESIN_CONF"

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

    # Default 관리자 계정명 변경 점검
    # 공통 함수: XML 주석 제거 (한 줄 및 여러 줄 주석 모두 제거)
    remove_xml_comments() {
        local FILE="$1"
        if [ -f "$FILE" ]; then
            if command -v perl &>/dev/null; then
                perl -0777 -pe 's/<!--.*?-->//gs' "$FILE"
            else
                awk '
                BEGIN { in_comment = 0 }
                {
                    while (1) {
                        if (in_comment) {
                            if (match($0, /-->/)) {
                                $0 = substr($0, RSTART + RLENGTH)
                                in_comment = 0
                            } else {
                                $0 = ""
                                break
                            }
                        }
                        if (match($0, /<!--/)) {
                            before = substr($0, 1, RSTART - 1)
                            after = substr($0, RSTART + 4)
                            if (match(after, /-->/)) {
                                $0 = before substr(after, RSTART + RLENGTH)
                            } else {
                                $0 = before
                                in_comment = 1
                                break
                            }
                        } else {
                            break
                        }
                    }
                    if ($0 != "" || !in_comment) print
                }
                ' "$FILE"
            fi
        fi
    }

    # XML 내용에서 특정 패턴이 주석 안에 있는지 확인
    # 반환값: "COMMENTED" 또는 "ACTIVE" 또는 "NOT_FOUND"
    check_comment_status() {
        local FILE="$1"
        local PATTERN="$2"

        if [ ! -f "$FILE" ]; then
            echo "NOT_FOUND"
            return
        fi

        local ORIGINAL_MATCH=$(grep -i "$PATTERN" "$FILE" 2>/dev/null)

        if [ -z "$ORIGINAL_MATCH" ]; then
            echo "NOT_FOUND"
            return
        fi

        local CLEANED_MATCH=$(remove_xml_comments "$FILE" | grep -i "$PATTERN" 2>/dev/null)

        if [ -z "$CLEANED_MATCH" ]; then
            echo "COMMENTED"
        else
            echo "ACTIVE"
        fi
    }


        if [ ! -f "$ADMIN_USERS_XML" ]; then
            RES="N/A"
            DESC="admin-users.xml 파일을 찾을 수 없음"
            DT="ADMIN_USERS_XML: ${ADMIN_USERS_XML} (파일 없음)"
        else
            # AdminAuthenticator 활성 여부 확인
            local ADMIN_AUTH_STATUS=$(check_comment_status "$RESIN_XML" "AdminAuthenticator")

            # 주석 제거 후 계정 추출
            local CLEANED_CONTENT=$(remove_xml_comments "$ADMIN_USERS_XML")
            local USER_NAMES=$(echo "$CLEANED_CONTENT" | grep -oP 'name="[^"]*"' 2>/dev/null)

            if [ "$ADMIN_AUTH_STATUS" != "ACTIVE" ] && [ -z "$USER_NAMES" ]; then
                RES="Y"
                DESC="/resin-admin 비활성 또는 관리자 계정 없음"
                DT="AdminAuthenticator: ${ADMIN_AUTH_STATUS}\n등록된 계정: 없음"
            elif [ -z "$USER_NAMES" ]; then
                RES="Y"
                DESC="관리자 계정이 등록되어 있지 않음"
                DT="AdminAuthenticator: ${ADMIN_AUTH_STATUS}\n등록된 계정: 없음"
            else
                # 기본 계정명(admin, resin, manager, root) 사용 여부 확인
                local DEFAULT_ACCOUNTS=$(echo "$CLEANED_CONTENT" | grep -iE 'name="(admin|resin|manager|root)"' 2>/dev/null)

                if [ -z "$DEFAULT_ACCOUNTS" ]; then
                    RES="Y"
                    DESC="기본 관리자 계정명이 변경되어 있음"
                    DT="AdminAuthenticator: ${ADMIN_AUTH_STATUS}\n등록된 계정:\n${USER_NAMES}\n기본 계정명(admin/resin/manager/root): 미사용"
                else
                    RES="N"
                    DESC="기본 관리자 계정명이 사용되고 있음"
                    DT="AdminAuthenticator: ${ADMIN_AUTH_STATUS}\n발견된 기본 계정:\n${DEFAULT_ACCOUNTS}"
                fi
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

    # 취약한 비밀번호 사용 제한 점검
        if [ ! -f "$ADMIN_USERS_XML" ]; then
            RES="N/A"
            DESC="admin-users.xml 파일을 찾을 수 없음"
            DT="ADMIN_USERS_XML: ${ADMIN_USERS_XML} (파일 없음)"
        else
            # 주석 제거 후 계정/비밀번호 추출
            local CLEANED_CONTENT=$(remove_xml_comments "$ADMIN_USERS_XML")
            local USER_ENTRIES=$(echo "$CLEANED_CONTENT" | grep -i '<user' 2>/dev/null)

            if [ -z "$USER_ENTRIES" ]; then
                RES="N/A"
                DESC="관리자 계정이 등록되어 있지 않음"
                DT="등록된 계정: 없음"
            else
                # password-digest 설정 확인
                local PW_DIGEST=$(grep -i 'password-digest' "$RESIN_XML" 2>/dev/null)
                local DIGEST_NONE=$(echo "$PW_DIGEST" | grep -i 'password-digest="none"' 2>/dev/null)

                if [ -n "$DIGEST_NONE" ]; then
                    RES="N"
                    DESC="비밀번호가 평문으로 저장되어 있음 (password-digest=none)"
                    DT="password-digest: none (평문 저장)\n설정 위치: ${RESIN_XML}\n${PW_DIGEST}"
                else
                    # 비밀번호 값 추출
                    local PASSWORDS=$(grep -i 'password' "$ADMIN_USERS_XML" 2>/dev/null)
                    local PW_VALUES=$(echo "$CLEANED_CONTENT" | grep -oP 'password="[^"]*"' 2>/dev/null)

                    local NON_HASH_FOUND=""
                    local TOTAL_PW=0
                    local PW_DETAILS=""

                    while IFS= read -r pw_entry; do
                        [ -z "$pw_entry" ] && continue
                        TOTAL_PW=$((TOTAL_PW + 1))
                        # password="값" 에서 값만 추출
                        local PW_VAL=$(echo "$pw_entry" | sed 's/password="//;s/"$//')

                        # MD5-Base64 해시 판별: 20자 이상의 [A-Za-z0-9+/] + 선택적 == 패딩
                        if echo "$PW_VAL" | grep -qE '^[A-Za-z0-9+/]{20,}={0,2}$'; then
                            PW_DETAILS="${PW_DETAILS}\n- ${pw_entry} [해시]"
                        else
                            NON_HASH_FOUND="Y"
                            PW_DETAILS="${PW_DETAILS}\n- ${pw_entry} [평문 의심]"
                        fi
                    done <<< "$PW_VALUES"

                    if [ "$NON_HASH_FOUND" = "Y" ]; then
                        RES="N"
                        DESC="해시되지 않은 비밀번호가 발견됨"
                        DT="password-digest: ${PW_DIGEST:-미설정 (기본 md5-base64)}\n총 ${TOTAL_PW}개 비밀번호 확인${PW_DETAILS}"
                    else
                        RES="Y"
                        DESC="비밀번호가 해시(MD5-Base64)로 저장되어 있음"
                        DT="password-digest: ${PW_DIGEST:-미설정 (기본 md5-base64)}\n총 ${TOTAL_PW}개 비밀번호 확인${PW_DETAILS}"
                    fi
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

    # 비밀번호 파일 권한 관리 점검
        if [ ! -f "$ADMIN_USERS_XML" ]; then
            RES="N/A"
            DESC="admin-users.xml 파일을 찾을 수 없음"
            DT="ADMIN_USERS_XML: ${ADMIN_USERS_XML} (파일 없음)"
        else
            local FILE_STAT=$(stat -c "%a %U:%G" "$ADMIN_USERS_XML" 2>/dev/null)
            local FILE_PERM=$(echo "$FILE_STAT" | awk '{print $1}')
            local FILE_OWNER=$(echo "$FILE_STAT" | awk '{print $2}')

            if [ -n "$FILE_PERM" ]; then
                local PERM_NUM=$((10#$FILE_PERM))
                local GROUP_PERM=$((($PERM_NUM / 10) % 10))
                local OTHER_PERM=$(($PERM_NUM % 10))

                if [ "$GROUP_PERM" -eq 0 ] && [ "$OTHER_PERM" -eq 0 ]; then
                    RES="Y"
                    DESC="admin-users.xml 파일 권한이 적절하게 설정됨"
                    DT="${ADMIN_USERS_XML}\n권한: ${FILE_PERM}\n소유자: ${FILE_OWNER}"
                else
                    RES="N"
                    DESC="admin-users.xml 파일 권한이 600 초과"
                    DT="${ADMIN_USERS_XML}\n권한: ${FILE_PERM} (600 이하 권장)\n소유자: ${FILE_OWNER}"
                fi
            else
                RES="M"
                DESC="파일 권한을 확인할 수 없음"
                DT="${ADMIN_USERS_XML}\nstat 명령 실행 실패"
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

    # 웹 서비스 디렉터리 리스팅 방지 설정 점검
        # resin.xml에서 DirectoryServlet 확인
        local DIR_SERVLET_STATUS=$(check_comment_status "$RESIN_XML" "DirectoryServlet")

        # web.xml에서 listings 파라미터 확인
        local LISTINGS_STATUS=$(check_comment_status "$WEB_XML" "listings")

        local DETAILS=""
        local IS_VULNERABLE="N"

        # DirectoryServlet 상태 확인
        if [ "$DIR_SERVLET_STATUS" = "ACTIVE" ]; then
            IS_VULNERABLE="Y"
            DETAILS="DirectoryServlet: [ACTIVE] 활성화됨"
            local DIR_SERVLET_LINE=$(grep -i 'DirectoryServlet' "$RESIN_XML" 2>/dev/null)
            DETAILS="${DETAILS}\n  ${DIR_SERVLET_LINE}"
        elif [ "$DIR_SERVLET_STATUS" = "COMMENTED" ]; then
            DETAILS="DirectoryServlet: [COMMENTED] 주석 처리됨"
        else
            DETAILS="DirectoryServlet: 미설정"
        fi

        # listings 파라미터 상태 확인
        if [ "$LISTINGS_STATUS" = "ACTIVE" ]; then
            # listings가 true인지 확인
            local CLEANED_WEB=$(remove_xml_comments "$WEB_XML")
            local LISTINGS_TRUE=$(echo "$CLEANED_WEB" | grep -A5 -i "listings" 2>/dev/null | grep -i "true" 2>/dev/null)
            if [ -n "$LISTINGS_TRUE" ]; then
                IS_VULNERABLE="Y"
                DETAILS="${DETAILS}\nlistings: [ACTIVE] true 설정됨"
            else
                DETAILS="${DETAILS}\nlistings: [ACTIVE] false 설정됨"
            fi
        elif [ "$LISTINGS_STATUS" = "COMMENTED" ]; then
            DETAILS="${DETAILS}\nlistings: [COMMENTED] 주석 처리됨"
        else
            DETAILS="${DETAILS}\nlistings: 미설정"
        fi

        if [ "$IS_VULNERABLE" = "Y" ]; then
            RES="N"
            DESC="디렉터리 리스팅이 활성화되어 있음"
            DT="$DETAILS"
        else
            RES="Y"
            DESC="디렉터리 리스팅이 비활성화되어 있음"
            DT="$DETAILS"
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

    # 지정하지 않은 CGI/ISAPI 실행 제한 점검
        local RESIN_WEB_XML="${RESIN_CONF}/resin-web.xml"
        local CGI_FOUND=""
        local DETAILS=""

        # web.xml에서 CGIServlet/cgi 확인
        local CGI_WEB_STATUS=$(check_comment_status "$WEB_XML" "CGIServlet\|cgi")
        if [ "$CGI_WEB_STATUS" = "ACTIVE" ]; then
            CGI_FOUND="Y"
            local CGI_WEB_LINE=$(remove_xml_comments "$WEB_XML" | grep -iE '(CGIServlet|cgi)' 2>/dev/null)
            DETAILS="web.xml CGI: [ACTIVE] 활성화됨\n  ${CGI_WEB_LINE}"
        elif [ "$CGI_WEB_STATUS" = "COMMENTED" ]; then
            DETAILS="web.xml CGI: [COMMENTED] 주석 처리됨"
        else
            DETAILS="web.xml CGI: 미설정"
        fi

        # resin-web.xml에서 CGIServlet/cgi 확인
        if [ -f "$RESIN_WEB_XML" ]; then
            local CGI_RESINWEB_STATUS=$(check_comment_status "$RESIN_WEB_XML" "CGIServlet\|cgi")
            if [ "$CGI_RESINWEB_STATUS" = "ACTIVE" ]; then
                CGI_FOUND="Y"
                local CGI_RW_LINE=$(remove_xml_comments "$RESIN_WEB_XML" | grep -iE '(CGIServlet|cgi)' 2>/dev/null)
                DETAILS="${DETAILS}\nresin-web.xml CGI: [ACTIVE] 활성화됨\n  ${CGI_RW_LINE}"
            elif [ "$CGI_RESINWEB_STATUS" = "COMMENTED" ]; then
                DETAILS="${DETAILS}\nresin-web.xml CGI: [COMMENTED] 주석 처리됨"
            else
                DETAILS="${DETAILS}\nresin-web.xml CGI: 미설정"
            fi
        else
            DETAILS="${DETAILS}\nresin-web.xml: 파일 없음"
        fi

        if [ "$CGI_FOUND" = "Y" ]; then
            RES="N"
            DESC="CGI 실행이 활성화되어 있음"
            DT="$DETAILS"
        else
            RES="Y"
            DESC="CGI 실행이 제한되어 있음 (Resin은 CGI 기본 미내장)"
            DT="$DETAILS"
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

    # 웹 서비스 상위 디렉터리 접근 제한 설정 점검
        # Java WAS 특성상 docBase 외부 접근 기본 차단
        local DETAILS="Java WAS 특성: docBase 외부 접근 기본 차단"

        if [ ! -f "$RESIN_XML" ]; then
            RES="Y"
            DESC="resin.xml 파일이 없으나, Java WAS 기본 차단 상태로 양호"
            DT="${DETAILS}\nresin.xml: 파일 없음"
        else
            # 주석 제거 후 상위 디렉터리 접근 허용 설정 확인
            local CLEANED_CONTENT=$(remove_xml_comments "$RESIN_XML")

            # path-traversal 허용, file-servlet real-path 등 외부 경로 허용 설정 탐색
            local TRAVERSAL_SETTINGS=$(echo "$CLEANED_CONTENT" | grep -iE '(path-traversal|real-path|alias-directory|file-servlet)' 2>/dev/null)

            if [ -n "$TRAVERSAL_SETTINGS" ]; then
                RES="N"
                DESC="상위 디렉터리 접근 허용 설정이 발견됨"
                DT="${DETAILS}\n\n발견된 설정:\n${TRAVERSAL_SETTINGS}"
            else
                RES="Y"
                DESC="상위 디렉터리 접근 허용 설정이 없음 (기본 양호)"
                DT="${DETAILS}\n상위 디렉터리 접근 허용 설정: 없음"
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

    # 웹 서비스 경로 내 불필요한 파일 제거 점검
        local FOUND_ITEMS=""

        # webapps 디렉터리 확인
        if [ -d "$WEBAPPS_DIR" ]; then
            # 불필요한 기본 디렉터리 확인 (resin-doc, resin-admin)
            for app in resin-doc resin-admin; do
                if [ -d "${WEBAPPS_DIR}/${app}" ]; then
                    FOUND_ITEMS="${FOUND_ITEMS}\n- ${WEBAPPS_DIR}/${app} (기본 앱)"
                fi
            done

            # 불필요한 파일 확인
            local UNNECESSARY_FILES=$(find "$WEBAPPS_DIR" -name "*.bak" -o -name "*.old" -o -name "*.tmp" -o -name "README*" 2>/dev/null | head -20)
            if [ -n "$UNNECESSARY_FILES" ]; then
                while IFS= read -r f; do
                    [ -n "$f" ] && FOUND_ITEMS="${FOUND_ITEMS}\n- ${f}"
                done <<< "$UNNECESSARY_FILES"
            fi
        fi

        # doc 디렉터리 확인
        if [ -d "${RESIN_HOME}/doc" ]; then
            local DOC_FILES=$(ls "${RESIN_HOME}/doc" 2>/dev/null)
            if [ -n "$DOC_FILES" ]; then
                FOUND_ITEMS="${FOUND_ITEMS}\n- ${RESIN_HOME}/doc/ (문서 디렉터리 존재)"
            fi
        fi

        local WEBAPPS_LIST=$(ls "$WEBAPPS_DIR" 2>/dev/null)

        if [ -z "$FOUND_ITEMS" ]; then
            RES="Y"
            DESC="불필요한 파일 및 디렉터리가 없음"
            DT="webapps 디렉터리 목록:\n${WEBAPPS_LIST:-없음}\n\n불필요 파일: 없음\ndoc 디렉터리: 없음"
        else
            RES="N"
            DESC="불필요한 파일 또는 디렉터리가 존재함"
            DT="webapps 디렉터리 목록:\n${WEBAPPS_LIST:-없음}\n\n발견된 항목:${FOUND_ITEMS}"
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

    # 웹 서비스 파일 업로드 및 다운로드 용량 제한 점검
        local LIMIT_FOUND=""
        local DETAILS=""

        # resin.xml에서 upload-max, form-upload-max, multipart-config 확인
        if [ -f "$RESIN_XML" ]; then
            local RESIN_LIMITS=$(grep -iE '(upload-max|form-upload-max|multipart-config)' "$RESIN_XML" 2>/dev/null)
            if [ -n "$RESIN_LIMITS" ]; then
                LIMIT_FOUND="Y"
                DETAILS="resin.xml:\n${RESIN_LIMITS}"
            else
                DETAILS="resin.xml: 용량 제한 미설정"
            fi
        else
            DETAILS="resin.xml: 파일 없음"
        fi

        # web.xml에서 upload-max, form-upload-max, multipart-config 확인
        if [ -f "$WEB_XML" ]; then
            local WEB_LIMITS=$(grep -iE '(upload-max|form-upload-max|multipart-config)' "$WEB_XML" 2>/dev/null)
            if [ -n "$WEB_LIMITS" ]; then
                LIMIT_FOUND="Y"
                DETAILS="${DETAILS}\nweb.xml:\n${WEB_LIMITS}"
            else
                DETAILS="${DETAILS}\nweb.xml: 용량 제한 미설정"
            fi
        else
            DETAILS="${DETAILS}\nweb.xml: 파일 없음"
        fi

        if [ "$LIMIT_FOUND" = "Y" ]; then
            RES="Y"
            DESC="파일 업로드 용량 제한이 설정되어 있음"
            DT="$DETAILS"
        else
            RES="N"
            DESC="파일 업로드 용량 제한이 설정되지 않음"
            DT="$DETAILS"
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

    # 웹 서비스 프로세스 권한 제한 점검
        # Resin 프로세스 실행 계정 확인
        local RESIN_USERS=$(ps aux 2>/dev/null | grep '[r]esin' | awk '{print $1}' | sort -u)
        local ROOT_PROC=$(ps aux 2>/dev/null | grep '[r]esin' | grep "^root" | head -3)

        # resin.xml에서 user-name, group-name 확인
        local XML_USER=""
        local XML_GROUP=""
        if [ -f "$RESIN_XML" ]; then
            XML_USER=$(grep -iE '(user-name|group-name)' "$RESIN_XML" 2>/dev/null)
        fi

        # resin.properties에서 setuid_user, setuid_group 확인
        local PROP_USER=""
        if [ -f "$RESIN_PROPERTIES" ]; then
            PROP_USER=$(grep -iE '(setuid_user|setuid_group)' "$RESIN_PROPERTIES" 2>/dev/null)
        fi

        local DETAILS=""
        DETAILS="실행 계정: ${RESIN_USERS:-프로세스 없음}"
        [ -n "$XML_USER" ] && DETAILS="${DETAILS}\nresin.xml 설정:\n${XML_USER}"
        [ -n "$PROP_USER" ] && DETAILS="${DETAILS}\nresin.properties 설정:\n${PROP_USER}"

        if [ -z "$RESIN_USERS" ]; then
            RES="M"
            DESC="Resin 프로세스를 확인할 수 없음"
            DT="${DETAILS}\n\n[참고] Resin 프로세스가 실행 중이지 않거나 확인 불가"
        elif [ -n "$ROOT_PROC" ]; then
            RES="N"
            DESC="Resin이 root 권한으로 실행 중"
            local PROC_DETAIL=$(ps aux 2>/dev/null | grep '[r]esin' | head -5)
            DT="${DETAILS}\n\n[프로세스 상세]\n${PROC_DETAIL}"
        else
            RES="Y"
            DESC="Resin이 제한된 권한으로 실행 중"
            local PROC_DETAIL=$(ps aux 2>/dev/null | grep '[r]esin' | head -5)
            DT="${DETAILS}\n\n[프로세스 상세]\n${PROC_DETAIL}"
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

    # 불필요한 프록시 설정 제한 점검
        if [ ! -f "$RESIN_XML" ]; then
            RES="N/A"
            DESC="resin.xml 파일을 찾을 수 없음"
            DT="RESIN_XML: ${RESIN_XML} (파일 없음)"
        else
            local DETAILS=""

            # resin.xml에서 프록시 관련 설정 확인
            local PROXY_XML=$(grep -iE '(HttpProxy|LoadBalance|proxy-cache|Dispatch)' "$RESIN_XML" 2>/dev/null)

            # resin.properties에서 프록시 관련 설정 확인
            local PROXY_PROPS=""
            if [ -f "$RESIN_PROPERTIES" ]; then
                PROXY_PROPS=$(grep -iE '(proxy_cache|backend_servers)' "$RESIN_PROPERTIES" 2>/dev/null)
            fi

            if [ -n "$PROXY_XML" ]; then
                DETAILS="[resin.xml 프록시 설정]\n${PROXY_XML}"
            else
                DETAILS="[resin.xml 프록시 설정] 미설정"
            fi

            if [ -n "$PROXY_PROPS" ]; then
                DETAILS="${DETAILS}\n[resin.properties 프록시 설정]\n${PROXY_PROPS}"
            else
                DETAILS="${DETAILS}\n[resin.properties 프록시 설정] 미설정"
            fi

            if [ -z "$PROXY_XML" ] && [ -z "$PROXY_PROPS" ]; then
                RES="Y"
                DESC="프록시 관련 설정이 없음"
                DT="$DETAILS"
            else
                RES="M"
                DESC="프록시 설정이 존재함 (불필요 여부 수동 확인 필요)"
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

    # 웹 서비스 경로 설정 점검
        if [ ! -f "$RESIN_XML" ]; then
            RES="N/A"
            DESC="resin.xml 파일을 찾을 수 없음"
            DT="RESIN_XML: ${RESIN_XML} (파일 없음)"
        else
            # 주석 제거 후 경로 설정 확인
            local CLEANED_CONTENT=$(remove_xml_comments "$RESIN_XML")

            # web-app-deploy 및 root-directory 설정 추출
            local DEPLOY_PATHS=$(echo "$CLEANED_CONTENT" | grep -iE '(web-app-deploy|root-directory)' 2>/dev/null)

            local DETAILS=""
            if [ -n "$DEPLOY_PATHS" ]; then
                DETAILS="[경로 설정]\n${DEPLOY_PATHS}"
            else
                DETAILS="[경로 설정] web-app-deploy/root-directory 미설정"
            fi

            # 기본 webapps 경로 사용 여부 확인
            local DEFAULT_WEBAPPS=$(echo "$DEPLOY_PATHS" | grep -iE 'webapps' 2>/dev/null)

            if [ -z "$DEPLOY_PATHS" ]; then
                RES="N"
                DESC="웹 서비스 경로 설정이 없음 (기본 경로 사용)"
                DT="$DETAILS\n\n기본 webapps 경로가 사용되고 있으며, 경로 분리가 필요합니다."
            elif [ -n "$DEFAULT_WEBAPPS" ]; then
                RES="N"
                DESC="기본 webapps 경로를 사용하고 있어 경로 분리가 필요함"
                DT="$DETAILS"
            else
                RES="Y"
                DESC="웹 서비스 경로가 기본 경로와 분리되어 있음"
                DT="$DETAILS"
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

    # 웹 서비스 링크 사용 금지 점검
        RES="Y"
        DESC="Resin은 심볼릭 링크 허용 설정이 없어 기본 차단 상태"

        # 웹앱 디렉터리 내 심볼릭 링크 존재 여부 참고 기록
        local SYMLINKS=""
        if [ -d "$WEBAPPS_DIR" ]; then
            SYMLINKS=$(find "$WEBAPPS_DIR" -type l 2>/dev/null)
        fi

        if [ -n "$SYMLINKS" ]; then
            DT="Resin은 allowLinking 등 심볼릭 링크 허용 설정이 존재하지 않음 (Java WAS 기본 차단)\n\n[참고] 웹앱 디렉터리 내 심볼릭 링크 발견:\n${SYMLINKS}"
        else
            DT="Resin은 allowLinking 등 심볼릭 링크 허용 설정이 존재하지 않음 (Java WAS 기본 차단)\n\n[참고] 웹앱 디렉터리 내 심볼릭 링크: 없음"
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

    # 웹 서비스 설정 파일 노출 제한 점검
        if [ -z "$RESIN_CONF" ] || [ ! -d "$RESIN_CONF" ]; then
            RES="N/A"
            DESC="Resin 설정 디렉터리를 찾을 수 없음"
            DT="RESIN_CONF: ${RESIN_CONF:-not set} (디렉터리 없음)"
        else
            local HAS_ISSUE="N"
            local DETAILS=""

            # 주요 설정 파일 권한 확인
            local CONFIG_FILES=("$RESIN_XML" "$RESIN_PROPERTIES" "$ADMIN_USERS_XML")
            for conf_file in "${CONFIG_FILES[@]}"; do
                if [ -f "$conf_file" ]; then
                    local FILE_INFO=$(stat -c "%n %a" "$conf_file" 2>/dev/null)
                    local FILE_PERM=$(stat -c "%a" "$conf_file" 2>/dev/null)
                    local OTHER_PERM=${FILE_PERM: -1}

                    if [ -n "$FILE_PERM" ] && [ "$OTHER_PERM" -ne 0 ] 2>/dev/null; then
                        HAS_ISSUE="Y"
                        DETAILS="${DETAILS}\n${FILE_INFO} (other 접근 가능 - 취약)"
                    else
                        DETAILS="${DETAILS}\n${FILE_INFO} (양호)"
                    fi
                else
                    DETAILS="${DETAILS}\n${conf_file} (파일 없음)"
                fi
            done

            # resin.xml 내 database 태그 확인 (DB 연결정보 노출 여부)
            local DB_TAG=""
            if [ -f "$RESIN_XML" ]; then
                DB_TAG=$(grep -i '<database>' "$RESIN_XML" 2>/dev/null)
            fi

            if [ -n "$DB_TAG" ]; then
                DETAILS="${DETAILS}\n\n[DB 연결정보] resin.xml에 <database> 설정 존재 (권한 관리 주의)"
            fi

            if [ "$HAS_ISSUE" = "N" ]; then
                RES="Y"
                DESC="설정 파일에 other 접근 권한이 없어 양호함"
                DT="[설정 파일 권한]${DETAILS}"
            else
                RES="N"
                DESC="설정 파일에 other 접근 권한이 존재하여 취약함"
                DT="[설정 파일 권한]${DETAILS}"
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

    # 웹 서비스 경로 내 파일의 접근 통제 점검
        if [ -z "$RESIN_CONF" ] || [ ! -d "$RESIN_CONF" ]; then
            RES="N/A"
            DESC="Resin 설정 디렉터리를 찾을 수 없음"
            DT="RESIN_CONF: ${RESIN_CONF:-not set} (디렉터리 없음)"
        else
            # 설정 디렉터리 내 other 읽기 가능한 파일 확인
            local OTHER_READABLE=$(find "$RESIN_CONF" -type f -perm /o=r 2>/dev/null)

            if [ -z "$OTHER_READABLE" ]; then
                RES="Y"
                DESC="설정 디렉터리 내 모든 파일에 other 접근 권한이 없음"
                DT="[점검 대상] ${RESIN_CONF}\nother 읽기 가능 파일: 없음"
            else
                local FILE_COUNT=$(echo "$OTHER_READABLE" | wc -l)
                local FILE_LIST=$(echo "$OTHER_READABLE" | head -20)
                RES="N"
                DESC="설정 디렉터리 내 other 접근 가능 파일이 존재함 (${FILE_COUNT}개)"
                DT="[점검 대상] ${RESIN_CONF}\n[other 읽기 가능 파일 (${FILE_COUNT}개)]\n${FILE_LIST}"
                if [ "$FILE_COUNT" -gt 20 ]; then
                    DT="${DT}\n... 외 $((FILE_COUNT - 20))개"
                fi
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

    # 웹 서비스의 불필요한 스크립트 매핑 제거 점검
        local DETAILS=""
        local HAS_ACTIVE="N"
        local APP_DEFAULT="${RESIN_CONF}/app-default.xml"
        local CHECK_FILES=""

        # 점검 대상 파일 목록 구성
        if [ -f "$WEB_XML" ]; then
            CHECK_FILES="$WEB_XML"
        fi
        if [ -f "$APP_DEFAULT" ]; then
            CHECK_FILES="${CHECK_FILES:+${CHECK_FILES} }${APP_DEFAULT}"
        fi

        if [ -z "$CHECK_FILES" ]; then
            RES="Y"
            DESC="web.xml 및 app-default.xml 파일이 없어 불필요한 매핑 없음"
            DT="WEB_XML: ${WEB_XML} (파일 없음)\napp-default.xml: ${APP_DEFAULT} (파일 없음)"
        else
            # 각 패턴별 점검
            local PATTERNS=("invoker" "SSIServlet" "SSIFilter" "CGIServlet")
            local PATTERN_NAMES=("invoker 서블릿" "SSIServlet" "SSIFilter" "CGIServlet")

            local i=0
            for pattern in "${PATTERNS[@]}"; do
                local STATUS="NOT_FOUND"

                # web.xml 점검
                if [ -f "$WEB_XML" ]; then
                    local WEB_STATUS=$(check_comment_status "$WEB_XML" "$pattern")
                    if [ "$WEB_STATUS" = "ACTIVE" ]; then
                        STATUS="ACTIVE"
                    elif [ "$WEB_STATUS" = "COMMENTED" ] && [ "$STATUS" != "ACTIVE" ]; then
                        STATUS="COMMENTED"
                    fi
                fi

                # app-default.xml 점검
                if [ -f "$APP_DEFAULT" ]; then
                    local APP_STATUS=$(check_comment_status "$APP_DEFAULT" "$pattern")
                    if [ "$APP_STATUS" = "ACTIVE" ]; then
                        STATUS="ACTIVE"
                    elif [ "$APP_STATUS" = "COMMENTED" ] && [ "$STATUS" != "ACTIVE" ]; then
                        STATUS="COMMENTED"
                    fi
                fi

                # 상태 기록
                if [ "$STATUS" = "NOT_FOUND" ]; then
                    DETAILS="${DETAILS}\n${PATTERN_NAMES[$i]}: 미설정"
                elif [ "$STATUS" = "COMMENTED" ]; then
                    DETAILS="${DETAILS}\n${PATTERN_NAMES[$i]}: [COMMENTED] 주석 처리됨"
                else
                    DETAILS="${DETAILS}\n${PATTERN_NAMES[$i]}: [ACTIVE] 활성화됨"
                    HAS_ACTIVE="Y"
                fi

                i=$((i + 1))
            done

            if [ "$HAS_ACTIVE" = "N" ]; then
                RES="Y"
                DESC="불필요한 스크립트 매핑이 없음 (활성화된 설정 없음)"
                DT="[점검 파일] ${CHECK_FILES}${DETAILS}"
            else
                RES="N"
                DESC="불필요한 스크립트 매핑이 활성화되어 있음"
                DT="[점검 파일] ${CHECK_FILES}${DETAILS}"
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

    # 웹 서비스 헤더 정보 노출 제한 점검
        if [ ! -f "$RESIN_XML" ]; then
            RES="N/A"
            DESC="resin.xml 파일을 찾을 수 없음"
            DT="RESIN_XML: ${RESIN_XML} (파일 없음)"
        else
            local DETAILS=""

            # resin.xml에서 server-header 속성 확인
            local SERVER_HEADER_XML=$(grep -i 'server-header' "$RESIN_XML" 2>/dev/null)

            # resin.properties에서 server_header 확인
            local SERVER_HEADER_PROPS=""
            if [ -f "$RESIN_PROPERTIES" ]; then
                SERVER_HEADER_PROPS=$(grep -i 'server_header' "$RESIN_PROPERTIES" 2>/dev/null)
            fi

            if [ -n "$SERVER_HEADER_XML" ]; then
                DETAILS="[resin.xml] server-header:\n${SERVER_HEADER_XML}"
            else
                DETAILS="[resin.xml] server-header: 미설정"
            fi

            if [ -n "$SERVER_HEADER_PROPS" ]; then
                DETAILS="${DETAILS}\n[resin.properties] server_header:\n${SERVER_HEADER_PROPS}"
            else
                DETAILS="${DETAILS}\n[resin.properties] server_header: 미설정"
            fi

            # 주석 제거 후 실제 활성 설정 확인
            local CLEANED_CONTENT=$(remove_xml_comments "$RESIN_XML")
            local ACTIVE_HEADER=$(echo "$CLEANED_CONTENT" | grep -i 'server-header' 2>/dev/null)

            if [ -n "$ACTIVE_HEADER" ]; then
                # server-header가 빈 값인지 확인 (빈 값 = 노출 차단)
                local HEADER_VALUE=$(echo "$ACTIVE_HEADER" | grep -oP 'server-header\s*=\s*"\K[^"]*' 2>/dev/null)
                if [ -z "$HEADER_VALUE" ]; then
                    RES="Y"
                    DESC="server-header가 빈 값으로 설정되어 서버 정보 노출이 차단됨"
                else
                    RES="Y"
                    DESC="server-header가 변경되어 기본 서버 정보가 노출되지 않음"
                fi
                DT="$DETAILS"
            elif [ -n "$SERVER_HEADER_PROPS" ]; then
                RES="Y"
                DESC="resin.properties에서 server_header가 설정됨"
                DT="$DETAILS"
            else
                RES="N"
                DESC="server-header 미설정으로 기본 Resin 버전 정보가 노출됨"
                DT="${DETAILS}\n\n기본값: Resin/x.x.x 버전 정보가 HTTP 응답 헤더에 노출됩니다."
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

    # 웹 서비스 가상 디렉터리 삭제 점검
        if [ ! -f "$RESIN_XML" ]; then
            RES="N/A"
            DESC="resin.xml 파일을 찾을 수 없음"
            DT="RESIN_XML: ${RESIN_XML} (파일 없음)"
        else
            # 주석 제거 후 web-app 태그 확인
            local CLEANED_CONTENT=$(remove_xml_comments "$RESIN_XML")
            local WEB_APP_TAGS=$(echo "$CLEANED_CONTENT" | grep -iE '<web-app' 2>/dev/null)

            if [ -z "$WEB_APP_TAGS" ]; then
                RES="Y"
                DESC="가상 디렉터리(web-app) 설정이 없음"
                DT="resin.xml 내 <web-app> 태그: 미설정"
            else
                local APP_COUNT=$(echo "$WEB_APP_TAGS" | wc -l)
                RES="M"
                DESC="가상 디렉터리(web-app) 설정이 존재함 (불필요 여부 수동 확인 필요)"
                DT="[web-app 설정 (${APP_COUNT}개)]\n${WEB_APP_TAGS}"
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

    # 웹 서비스 WebDAV 비활성화 점검
        RES="N/A"
        DESC="Resin은 WebDAV 모듈 기본 미내장"

        # web.xml에서 WebDAV 설정 참고 확인
        local WEBDAV_FOUND=""
        if [ -f "$WEB_XML" ]; then
            WEBDAV_FOUND=$(grep -iE '(webdav|WebdavServlet)' "$WEB_XML" 2>/dev/null)
        fi

        if [ -n "$WEBDAV_FOUND" ]; then
            DT="Resin은 WebDAV 모듈이 기본 내장되어 있지 않습니다.\n\n[참고] web.xml에서 WebDAV 관련 설정 발견:\n${WEBDAV_FOUND}"
        else
            DT="Resin은 WebDAV 모듈이 기본 내장되어 있지 않습니다.\nweb.xml에서도 WebDAV 관련 설정이 발견되지 않았습니다."
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

    # 웹 서비스 SSI(Server Side Includes) 사용 제한 점검
        if [ -z "$WEB_XML" ] || [ ! -f "$WEB_XML" ]; then
            RES="N/A"
            DESC="web.xml 파일을 찾을 수 없음"
            DT="WEB_XML: not found"
        else
            # SSI 서블릿/필터 주석 상태 확인
            local SSI_SERVLET_STATUS=$(check_comment_status "$WEB_XML" "SSIServlet")
            local SSI_FILTER_STATUS=$(check_comment_status "$WEB_XML" "SSIFilter")
            local SSI_MAPPING_STATUS=$(check_comment_status "$WEB_XML" "\.shtml")

            local DETAILS=""
            local HAS_ACTIVE="N"

            # SSIServlet 상태 표시
            if [ "$SSI_SERVLET_STATUS" = "NOT_FOUND" ]; then
                DETAILS="SSIServlet: 미설정"
            elif [ "$SSI_SERVLET_STATUS" = "COMMENTED" ]; then
                DETAILS="SSIServlet: [COMMENTED] 주석 처리됨"
            else
                DETAILS="SSIServlet: [ACTIVE] 활성화됨"
                HAS_ACTIVE="Y"
            fi

            # SSIFilter 상태 표시
            if [ "$SSI_FILTER_STATUS" = "NOT_FOUND" ]; then
                DETAILS="$DETAILS\nSSIFilter: 미설정"
            elif [ "$SSI_FILTER_STATUS" = "COMMENTED" ]; then
                DETAILS="$DETAILS\nSSIFilter: [COMMENTED] 주석 처리됨"
            else
                DETAILS="$DETAILS\nSSIFilter: [ACTIVE] 활성화됨"
                HAS_ACTIVE="Y"
            fi

            # .shtml 매핑 상태 표시
            if [ "$SSI_MAPPING_STATUS" = "NOT_FOUND" ]; then
                DETAILS="$DETAILS\n.shtml 매핑: 미설정"
            elif [ "$SSI_MAPPING_STATUS" = "COMMENTED" ]; then
                DETAILS="$DETAILS\n.shtml 매핑: [COMMENTED] 주석 처리됨"
            else
                DETAILS="$DETAILS\n.shtml 매핑: [ACTIVE] 활성화됨"
                HAS_ACTIVE="Y"
            fi

            # 결과 판정
            if [ "$HAS_ACTIVE" = "N" ]; then
                RES="Y"
                DESC="SSI가 비활성화되어 있음 (설정 없음 또는 주석 처리됨)"
                DT="Resin은 SSI를 기본 내장하지 않습니다.\n설정파일: $WEB_XML\n\n$DETAILS"
            else
                RES="N"
                DESC="SSI가 활성화되어 있음"
                DT="설정파일: $WEB_XML\n\n$DETAILS"
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

    # SSL/TLS 활성화 점검
        RES="N/A"
        DESC="앞단 웹서버(Apache/Nginx)에서 SSL 처리"
        local SSL_INFO=""

        # resin.xml에서 SSL 관련 설정 참고 수집
        if [ -f "$RESIN_XML" ]; then
            local OPENSSL_CONF=$(grep -i 'openssl' "$RESIN_XML" 2>/dev/null)
            local JSSE_CONF=$(grep -i 'jsse-ssl' "$RESIN_XML" 2>/dev/null)
            local SSL_CTX=$(grep -i 'ssl-context' "$RESIN_XML" 2>/dev/null)

            if [ -n "$OPENSSL_CONF" ]; then
                SSL_INFO="openssl 설정 발견:\n$OPENSSL_CONF"
            fi
            if [ -n "$JSSE_CONF" ]; then
                SSL_INFO="${SSL_INFO:+$SSL_INFO\n\n}jsse-ssl 설정 발견:\n$JSSE_CONF"
            fi
            if [ -n "$SSL_CTX" ]; then
                SSL_INFO="${SSL_INFO:+$SSL_INFO\n\n}ssl-context 설정 발견:\n$SSL_CTX"
            fi
        fi

        if [ -n "$SSL_INFO" ]; then
            DT="일반적으로 앞단 웹서버(Apache/Nginx)에서 SSL/TLS를 처리하므로 N/A 처리합니다.\n\n[참고] Resin 자체 SSL 설정이 존재합니다:\n$SSL_INFO\n\n설정파일: $RESIN_XML"
        else
            DT="일반적으로 앞단 웹서버(Apache/Nginx)에서 SSL/TLS를 처리하므로 N/A 처리합니다.\n\nResin 자체 SSL 설정(openssl/jsse-ssl/ssl-context): 미발견\n설정파일: ${RESIN_XML:-N/A}"
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

    # HTTP 리디렉션 점검
        RES="N/A"
        DESC="앞단 웹서버에서 HTTPS 리디렉션 처리"
        DT="HTTP에서 HTTPS로의 리디렉션은 일반적으로 앞단 웹서버(Apache/Nginx)에서 처리합니다.\nResin 단독 구성 시에는 web.xml의 security-constraint를 통해 HTTPS 강제가 가능하나,\n앞단 웹서버 사용 환경에서는 해당 웹서버 설정을 점검해야 합니다."

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

    # 에러 페이지 관리 점검
        local ERROR_FOUND="N"
        local ALL_DETAILS=""

        # web.xml 확인
        if [ -f "$WEB_XML" ]; then
            local WEB_ERROR=$(grep -A2 '<error-page>' "$WEB_XML" 2>/dev/null)
            if [ -n "$WEB_ERROR" ]; then
                ERROR_FOUND="Y"
                ALL_DETAILS="[web.xml] error-page 설정:\n$WEB_ERROR"
            else
                ALL_DETAILS="[web.xml] error-page: 미설정"
            fi
        else
            ALL_DETAILS="[web.xml] 파일 없음: ${WEB_XML:-N/A}"
        fi

        # resin-web.xml 확인
        local RESIN_WEB_XML="${RESIN_CONF}/resin-web.xml"
        if [ -f "$RESIN_WEB_XML" ]; then
            local RESIN_WEB_ERROR=$(grep -A2 '<error-page>' "$RESIN_WEB_XML" 2>/dev/null)
            if [ -n "$RESIN_WEB_ERROR" ]; then
                ERROR_FOUND="Y"
                ALL_DETAILS="$ALL_DETAILS\n\n[resin-web.xml] error-page 설정:\n$RESIN_WEB_ERROR"
            else
                ALL_DETAILS="$ALL_DETAILS\n\n[resin-web.xml] error-page: 미설정"
            fi
        else
            ALL_DETAILS="$ALL_DETAILS\n\n[resin-web.xml] 파일 없음: $RESIN_WEB_XML"
        fi

        if [ "$ERROR_FOUND" = "Y" ]; then
            RES="Y"
            DESC="에러 페이지가 설정되어 있음"
            DT="$ALL_DETAILS"
        else
            RES="N"
            DESC="에러 페이지가 설정되지 않음"
            DT="$ALL_DETAILS\n\n[취약] error-page 설정을 통해 사용자 정의 에러 페이지를 지정해야 합니다."
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

    # LDAP 알고리즘 적절하게 구성 점검
        if [ ! -f "$RESIN_XML" ]; then
            RES="N/A"
            DESC="resin.xml 파일을 찾을 수 없음"
            DT="RESIN_XML: not found"
        else
            # LDAP Authenticator 설정 확인
            local LDAP_AUTH=$(grep -iE '(LdapAuthenticator|JndiAuthenticator)' "$RESIN_XML" 2>/dev/null | grep -v "^\s*<!--")

            if [ -z "$LDAP_AUTH" ]; then
                RES="N/A"
                DESC="LDAP 인증이 설정되지 않음"
                DT="LdapAuthenticator / JndiAuthenticator: 미사용\n설정파일: $RESIN_XML"
            else
                # password-digest 설정 확인
                local DIGEST=$(grep -i 'password-digest' "$RESIN_XML" 2>/dev/null | grep -v "^\s*<!--")
                local DIGEST_VALUE=""
                if [ -n "$DIGEST" ]; then
                    DIGEST_VALUE=$(echo "$DIGEST" | grep -oP '>\K[^<]+' 2>/dev/null | head -1)
                    if [ -z "$DIGEST_VALUE" ]; then
                        DIGEST_VALUE=$(echo "$DIGEST" | sed -n 's/.*password-digest[^>]*>\([^<]*\).*/\1/p' 2>/dev/null | head -1)
                    fi
                fi

                if [ -z "$DIGEST" ]; then
                    RES="N"
                    DESC="LDAP 비밀번호 다이제스트 알고리즘이 설정되지 않음 (평문 전송 가능)"
                    DT="LDAP 인증 사용 중:\n$LDAP_AUTH\n\npassword-digest: 미설정\n설정파일: $RESIN_XML"
                elif echo "$DIGEST_VALUE" | grep -qiE '(SHA-256|SHA-384|SHA-512|SHA256|SHA384|SHA512)'; then
                    RES="Y"
                    DESC="안전한 다이제스트 알고리즘 사용 중"
                    DT="LDAP 인증 사용 중:\n$LDAP_AUTH\n\npassword-digest: $DIGEST_VALUE\n설정파일: $RESIN_XML"
                elif echo "$DIGEST_VALUE" | grep -qiE '(MD5|SHA-1|SHA1|none)'; then
                    RES="N"
                    DESC="취약한 다이제스트 알고리즘 사용 중"
                    DT="LDAP 인증 사용 중:\n$LDAP_AUTH\n\npassword-digest: $DIGEST_VALUE (SHA-256 이상 권장)\n설정파일: $RESIN_XML"
                else
                    RES="M"
                    DESC="다이제스트 알고리즘 수동 확인 필요"
                    DT="LDAP 인증 사용 중:\n$LDAP_AUTH\n\npassword-digest: $DIGEST_VALUE\n설정파일: $RESIN_XML"
                fi
            fi
        fi

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

    # 별도의 업로드 경로 사용 및 권한 설정 점검
        if [ -z "$WEBAPPS_DIR" ] || [ ! -d "$WEBAPPS_DIR" ]; then
            RES="N"
            DESC="웹앱 디렉터리를 찾을 수 없음"
            DT="WEBAPPS_DIR: ${WEBAPPS_DIR:-not set} (디렉터리 없음)"
        else
            # 업로드 디렉터리 탐색
            local UPLOAD_DIRS=$(find "$WEBAPPS_DIR" -type d -name "upload*" 2>/dev/null)

            if [ -z "$UPLOAD_DIRS" ]; then
                RES="N"
                DESC="별도 업로드 경로가 존재하지 않음"
                DT="검색 경로: $WEBAPPS_DIR\n검색 패턴: upload*\n결과: 별도 업로드 디렉터리 미발견\n\n별도의 업로드 경로를 분리하여 사용해야 합니다."
            else
                local HAS_OTHER="N"
                local DETAILS=""

                while IFS= read -r dir; do
                    local PERM=$(stat -c "%a" "$dir" 2>/dev/null)
                    local OWNER=$(stat -c "%U:%G" "$dir" 2>/dev/null)
                    local OTHER_PERM=${PERM: -1}
                    DETAILS="$DETAILS\n$dir - 권한: $PERM, 소유자: $OWNER"

                    if [ "$OTHER_PERM" -ne 0 ] 2>/dev/null; then
                        HAS_OTHER="Y"
                        DETAILS="$DETAILS (other 접근 가능)"
                    fi
                done <<< "$UPLOAD_DIRS"

                if [ "$HAS_OTHER" = "Y" ]; then
                    RES="N"
                    DESC="업로드 디렉터리에 일반 사용자 접근 권한이 있음"
                    DT="검색 경로: $WEBAPPS_DIR\n발견된 업로드 디렉터리:$DETAILS\n\nother 권한 제거가 필요합니다."
                else
                    RES="Y"
                    DESC="업로드 디렉터리에 적절한 권한이 설정됨"
                    DT="검색 경로: $WEBAPPS_DIR\n발견된 업로드 디렉터리:$DETAILS"
                fi
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

    # 주기적 보안 패치 및 벤더 권고사항 적용 점검
        RES="M"
        local VERSION_INFO=""
        local MANIFEST_INFO=""

        # resin.jar를 통한 버전 확인
        if [ -f "${RESIN_HOME}/lib/resin.jar" ]; then
            VERSION_INFO=$(java -jar "${RESIN_HOME}/lib/resin.jar" version 2>/dev/null | head -5)
            MANIFEST_INFO=$(unzip -p "${RESIN_HOME}/lib/resin.jar" META-INF/MANIFEST.MF 2>/dev/null | grep -i version)
        fi

        if [ -n "$VERSION_INFO" ] || [ -n "$MANIFEST_INFO" ]; then
            DESC="Resin 버전 정보 확인 (수동 패치 확인 필요)"
            local DT_TEXT="[Resin 버전 정보]"
            if [ -n "$VERSION_INFO" ]; then
                DT_TEXT="$DT_TEXT\nresin.jar version:\n$VERSION_INFO"
            fi
            if [ -n "$MANIFEST_INFO" ]; then
                DT_TEXT="$DT_TEXT\n\nMANIFEST.MF:\n$MANIFEST_INFO"
            fi
            DT="$DT_TEXT\n\n최신 버전 확인: https://www.caucho.com/\n수동으로 최신 패치 적용 여부를 확인해야 합니다."
        else
            DESC="Resin 버전을 확인할 수 없음 (수동 확인 필요)"
            DT="resin.jar 경로: ${RESIN_HOME}/lib/resin.jar\n버전 정보를 추출할 수 없습니다.\n\n최신 버전 확인: https://www.caucho.com/"
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

    # 로그 디렉터리 및 파일 권한 설정 점검
        local LOG_PATHS=("${RESIN_HOME}/log" "/var/log/resin" "/var/log/caucho")
        local FOUND_ANY="N"
        local HAS_OTHER="N"
        local ALL_DETAILS=""

        for d in "${LOG_PATHS[@]}"; do
            if [ -d "$d" ]; then
                FOUND_ANY="Y"
                local DIR_PERM=$(stat -c "%a" "$d" 2>/dev/null)
                local DIR_OWNER=$(stat -c "%U:%G" "$d" 2>/dev/null)
                local DIR_OTHER=${DIR_PERM: -1}
                local DIR_LISTING=$(ls -la "$d" 2>/dev/null | head -5)

                ALL_DETAILS="$ALL_DETAILS\n[디렉터리] $d - 권한: $DIR_PERM, 소유자: $DIR_OWNER"

                # 디렉터리 other 권한 확인
                if [ "$DIR_OTHER" -ne 0 ] 2>/dev/null; then
                    HAS_OTHER="Y"
                    ALL_DETAILS="$ALL_DETAILS (other 접근 가능)"
                fi

                # 로그 파일 other 권한 확인
                local OTHER_FILES=$(find "$d" -type f -perm /o=r 2>/dev/null | head -5)
                if [ -n "$OTHER_FILES" ]; then
                    HAS_OTHER="Y"
                    while IFS= read -r f; do
                        local F_PERM=$(stat -c "%a" "$f" 2>/dev/null)
                        ALL_DETAILS="$ALL_DETAILS\n  [파일] $f - 권한: $F_PERM (other 읽기 가능)"
                    done <<< "$OTHER_FILES"
                fi

                ALL_DETAILS="$ALL_DETAILS\n  파일 목록:\n$DIR_LISTING"
            fi
        done

        if [ "$FOUND_ANY" = "N" ]; then
            RES="N"
            DESC="로그 디렉터리를 찾을 수 없음"
            DT="점검 경로:\n  - ${RESIN_HOME}/log\n  - /var/log/resin\n  - /var/log/caucho\n\n로그 디렉터리가 존재하지 않습니다."
        elif [ "$HAS_OTHER" = "Y" ]; then
            RES="N"
            DESC="로그 디렉터리 또는 파일에 일반 사용자 접근 권한이 있음"
            DT="$ALL_DETAILS\n\nother 권한 제거가 필요합니다."
        else
            RES="Y"
            DESC="로그 디렉터리 및 파일에 적절한 권한이 설정됨"
            DT="$ALL_DETAILS"
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
