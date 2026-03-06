#!/bin/bash
#================================================================
# Tomcat_Linux 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : Tomcat_Linux
# 항목  : WEB-01 ~ WEB-26 (26개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

# Tomcat 설치 경로 (자동 탐지 실패 시 수동 설정)
CATALINA_HOME=""
TOMCAT_CONF=""

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="Tomcat"
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
# Tomcat 설치 경로 자동 탐지
detect_tomcat() {
    # 환경 변수 확인
    if [ -n "$CATALINA_HOME" ] && [ -d "$CATALINA_HOME" ]; then
        TOMCAT_CONF="$CATALINA_HOME/conf"
        return
    fi

    # 일반적인 설치 경로 확인
    local COMMON_PATHS=(
        "/opt/tomcat"
        "/usr/share/tomcat"
        "/usr/share/tomcat9"
        "/usr/share/tomcat8"
        "/usr/share/tomcat7"
        "/var/lib/tomcat"
        "/var/lib/tomcat9"
        "/var/lib/tomcat8"
        "/var/lib/tomcat7"
        "/usr/local/tomcat"
        "/home/tomcat"
    )

    for path in "${COMMON_PATHS[@]}"; do
        if [ -d "$path" ] && [ -f "$path/conf/server.xml" ]; then
            CATALINA_HOME="$path"
            TOMCAT_CONF="$path/conf"
            break
        fi
    done

    # 프로세스에서 CATALINA_HOME 추출
    if [ -z "$CATALINA_HOME" ]; then
        local PROC_HOME=$(ps aux 2>/dev/null | grep "catalina" | grep -v grep | head -1 | sed -n 's/.*-Dcatalina.home=\([^ ]*\).*/\1/p')
        if [ -n "$PROC_HOME" ] && [ -d "$PROC_HOME" ]; then
            CATALINA_HOME="$PROC_HOME"
            TOMCAT_CONF="$PROC_HOME/conf"
        fi
    fi

    # systemd에서 CATALINA_HOME 추출
    if [ -z "$CATALINA_HOME" ]; then
        local SYSTEMD_HOME=$(systemctl cat tomcat 2>/dev/null | grep "CATALINA_HOME" | cut -d'=' -f2 | tr -d '"' | head -1)
        if [ -n "$SYSTEMD_HOME" ] && [ -d "$SYSTEMD_HOME" ]; then
            CATALINA_HOME="$SYSTEMD_HOME"
            TOMCAT_CONF="$SYSTEMD_HOME/conf"
        fi
    fi
}

# Tomcat 탐지 실행
detect_tomcat

# Tomcat 버전 정보
TOMCAT_VERSION=""
if [ -n "$CATALINA_HOME" ] && [ -f "$CATALINA_HOME/lib/catalina.jar" ]; then
    TOMCAT_VERSION=$(java -cp "$CATALINA_HOME/lib/catalina.jar" org.apache.catalina.util.ServerInfo 2>/dev/null | grep "Server version" | head -1)
fi

# 주요 설정 파일 경로
SERVER_XML="${TOMCAT_CONF}/server.xml"
WEB_XML="${TOMCAT_CONF}/web.xml"
TOMCAT_USERS_XML="${TOMCAT_CONF}/tomcat-users.xml"
CONTEXT_XML="${TOMCAT_CONF}/context.xml"

SVC_VERSION="$TOMCAT_VERSION"
SVC_CONF="$TOMCAT_CONF"

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

    # 공통 함수: XML 주석 제거 (한 줄 및 여러 줄 주석 모두 제거)
    remove_xml_comments() {
        local FILE="$1"
        if [ -f "$FILE" ]; then
            # Perl이 있으면 Perl 사용 (가장 정확함)
            if command -v perl &>/dev/null; then
                perl -0777 -pe 's/<!--.*?-->//gs' "$FILE"
            else
                # Perl이 없으면 awk 사용 (여러 줄 주석 처리)
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

        # 원본 파일에서 패턴 존재 여부 확인
        local ORIGINAL_MATCH=$(grep -i "$PATTERN" "$FILE" 2>/dev/null)

        if [ -z "$ORIGINAL_MATCH" ]; then
            echo "NOT_FOUND"
            return
        fi

        # 주석 제거 후 패턴 존재 여부 확인
        local CLEANED_MATCH=$(remove_xml_comments "$FILE" | grep -i "$PATTERN" 2>/dev/null)

        if [ -z "$CLEANED_MATCH" ]; then
            echo "COMMENTED"
        else
            echo "ACTIVE"
        fi
    }


        if [ -z "$TOMCAT_USERS_XML" ] || [ ! -f "$TOMCAT_USERS_XML" ]; then
            RES="N/A"
            DESC="tomcat-users.xml 파일을 찾을 수 없음"
            DT="TOMCAT_USERS_XML: not found"
        else
            # 주석 제거 후 XML 내용 추출
            local CLEANED_CONTENT=$(remove_xml_comments "$TOMCAT_USERS_XML")

            # 기본 계정명(admin, tomcat, manager, root) 확인 (주석 제거된 내용에서)
            local DEFAULT_ACCOUNTS=$(echo "$CLEANED_CONTENT" | grep -E "username\s*=\s*\"(admin|tomcat|manager|root)\"" 2>/dev/null)

            # manager-gui, admin-gui 등 관리자 역할 확인 (주석 제거된 내용에서)
            local ADMIN_ROLES=$(echo "$CLEANED_CONTENT" | grep -E "roles\s*=\s*\"[^\"]*manager-gui[^\"]*\"" 2>/dev/null)

            if [ -z "$ADMIN_ROLES" ]; then
                RES="Y"
                DESC="관리자 페이지가 비활성화되어 있거나 관리자 계정이 없음"
                DT="관리자 역할: 미설정"
            elif [ -z "$DEFAULT_ACCOUNTS" ]; then
                RES="Y"
                DESC="기본 관리자 계정명이 변경되어 있음"
                DT="관리자 역할 설정 존재, 기본 계정명(admin, tomcat, manager, root) 미사용"
            else
                RES="N"
                DESC="기본 관리자 계정명이 사용되고 있음"
                DT="발견된 기본 계정:\n$DEFAULT_ACCOUNTS"
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

    if [ -z "$TOMCAT_USERS_XML" ] || [ ! -f "$TOMCAT_USERS_XML" ]; then
        RES="N/A"
        DESC="tomcat-users.xml 파일을 찾을 수 없음"
        DT="TOMCAT_USERS_XML: not found"
    else
        # 주석 제거 후 XML 내용에서 비밀번호 추출 (평문 비밀번호)
        local CLEANED_CONTENT=$(remove_xml_comments "$TOMCAT_USERS_XML")
        local PASSWORDS=$(echo "$CLEANED_CONTENT" | grep -oP 'password\s*=\s*"\K[^"]+' 2>/dev/null | grep -v "^\s*$")

        # 관리자 역할(manager-gui, admin-gui 등) 계정 존재 여부 확인
        local ADMIN_ROLES=$(echo "$CLEANED_CONTENT" | grep -iE 'roles\s*=\s*"[^"]*((manager|admin)-(gui|script|jmx|status))[^"]*"' 2>/dev/null)

        if [ -z "$PASSWORDS" ] && [ -z "$ADMIN_ROLES" ]; then
            RES="N/A"
            DESC="관리자 계정이 설정되어 있지 않음"
            DT="관리자 역할: 미설정\n비밀번호: 미설정"
        elif [ -z "$PASSWORDS" ]; then
            RES="Y"
            DESC="관리자 계정은 존재하나 비밀번호가 설정되지 않음"
            DT="비밀번호: 미설정"
        else
            local WEAK_PASS=""
            local TOTAL_PASS=0
            local WEAK_COUNT=0

            while IFS= read -r pass; do
                TOTAL_PASS=$((TOTAL_PASS + 1))
                local IS_WEAK="N"

                # 길이 체크 (8자 미만)
                if [ ${#pass} -lt 8 ]; then
                    IS_WEAK="Y"
                fi

                # 단순 비밀번호 체크
                if echo "$pass" | grep -qiE "^(password|admin|tomcat|123456|qwerty|1234|root|test)"; then
                    IS_WEAK="Y"
                fi

                # 숫자만으로 구성
                if echo "$pass" | grep -qE "^[0-9]+$"; then
                    IS_WEAK="Y"
                fi

                # 영문만으로 구성
                if echo "$pass" | grep -qE "^[a-zA-Z]+$"; then
                    IS_WEAK="Y"
                fi

                # 암호화된 비밀번호 (해시) 여부 확인 - SHA, MD5 등
                if echo "$pass" | grep -qE "^\{(SHA|MD5|SSHA|SHA-256|SHA-512)\}"; then
                    IS_WEAK="N"  # 암호화된 경우 양호
                fi

                if [ "$IS_WEAK" = "Y" ]; then
                    WEAK_COUNT=$((WEAK_COUNT + 1))
                    WEAK_PASS="$WEAK_PASS\n- 취약한 비밀번호 발견 (길이: ${#pass})"
                fi
            done <<< "$PASSWORDS"

            if [ "$WEAK_COUNT" -eq 0 ]; then
                RES="Y"
                DESC="비밀번호가 복잡도 기준을 충족함"
                DT="총 ${TOTAL_PASS}개 계정 확인, 취약한 비밀번호 없음"
            else
                RES="N"
                DESC="취약한 비밀번호가 발견됨"
                DT="총 ${TOTAL_PASS}개 계정 중 ${WEAK_COUNT}개 취약$WEAK_PASS"
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

    if [ -z "$TOMCAT_USERS_XML" ] || [ ! -f "$TOMCAT_USERS_XML" ]; then
        RES="N/A"
        DESC="tomcat-users.xml 파일을 찾을 수 없음"
        DT="TOMCAT_USERS_XML: not found"
    else
        local FILE_PERM=$(stat -c "%a" "$TOMCAT_USERS_XML" 2>/dev/null)
        local FILE_OWNER=$(stat -c "%U:%G" "$TOMCAT_USERS_XML" 2>/dev/null)

        # 권한을 숫자로 변환하여 비교 (600 이하)
        if [ -n "$FILE_PERM" ]; then
            local PERM_NUM=$((10#$FILE_PERM))
            local GROUP_PERM=$((($PERM_NUM / 10) % 10))
            local OTHER_PERM=$(($PERM_NUM % 10))

            if [ "$GROUP_PERM" -eq 0 ] && [ "$OTHER_PERM" -eq 0 ]; then
                RES="Y"
                DESC="tomcat-users.xml 파일 권한이 적절하게 설정됨"
                DT="$TOMCAT_USERS_XML\n권한: $FILE_PERM\n소유자: $FILE_OWNER"
            else
                RES="N"
                DESC="tomcat-users.xml 파일 권한이 600 초과"
                DT="$TOMCAT_USERS_XML\n권한: $FILE_PERM (600 이하 권장)\n소유자: $FILE_OWNER"
            fi
        else
            RES="M"
            DESC="파일 권한을 확인할 수 없음"
            DT="$TOMCAT_USERS_XML"
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

    if [ -z "$WEB_XML" ] || [ ! -f "$WEB_XML" ]; then
        RES="N/A"
        DESC="web.xml 파일을 찾을 수 없음"
        DT="WEB_XML: not found"
    else
        # listings 설정 확인
        local LISTINGS_TRUE=$(grep -A5 "<param-name>listings</param-name>" "$WEB_XML" 2>/dev/null | grep -i "<param-value>true</param-value>" | grep -v "^\s*<!--")
        local LISTINGS_FALSE=$(grep -A5 "<param-name>listings</param-name>" "$WEB_XML" 2>/dev/null | grep -i "<param-value>false</param-value>" | grep -v "^\s*<!--")

        if [ -n "$LISTINGS_TRUE" ]; then
            RES="N"
            DESC="디렉터리 리스팅이 활성화되어 있음"
            DT="listings=true 설정 발견"
        elif [ -n "$LISTINGS_FALSE" ]; then
            RES="Y"
            DESC="디렉터리 리스팅이 비활성화되어 있음"
            DT="listings=false"
        else
            # 기본값은 false
            RES="Y"
            DESC="디렉터리 리스팅 설정이 없음 (기본값: false)"
            DT="listings: 미설정 (기본값 false 적용)"
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

    if [ -z "$WEB_XML" ] || [ ! -f "$WEB_XML" ]; then
        RES="N/A"
        DESC="web.xml 파일을 찾을 수 없음"
        DT="WEB_XML: not found"
    else
        # CGI 서블릿 주석 상태 확인
        local CGI_SERVLET_STATUS=$(check_comment_status "$WEB_XML" "<servlet-name>cgi</servlet-name>")
        local CGI_MAPPING_STATUS=$(check_comment_status "$WEB_XML" "/cgi-bin/\*")

        # 주석 제거 후 XML 내용 추출
        local CLEANED_CONTENT=$(remove_xml_comments "$WEB_XML")

        # 주석 제거된 내용에서 CGI 설정 확인
        local CGI_SERVLET_ACTIVE=$(echo "$CLEANED_CONTENT" | grep -B5 -A5 "<servlet-name>cgi</servlet-name>" 2>/dev/null)
        local CGI_MAPPING_ACTIVE=$(echo "$CLEANED_CONTENT" | grep -B5 -A5 "/cgi-bin/\*" 2>/dev/null)

        local DETAILS=""

        # CGI 서블릿 상태 표시
        if [ "$CGI_SERVLET_STATUS" = "NOT_FOUND" ]; then
            DETAILS="CGI 서블릿: 미설정"
        elif [ "$CGI_SERVLET_STATUS" = "COMMENTED" ]; then
            DETAILS="CGI 서블릿: [COMMENTED] 주석 처리됨"
        else
            DETAILS="CGI 서블릿: [ACTIVE] 활성화됨"
        fi

        # CGI 매핑 상태 표시
        if [ "$CGI_MAPPING_STATUS" = "NOT_FOUND" ]; then
            DETAILS="$DETAILS\nCGI 매핑: 미설정"
        elif [ "$CGI_MAPPING_STATUS" = "COMMENTED" ]; then
            DETAILS="$DETAILS\nCGI 매핑: [COMMENTED] 주석 처리됨"
        else
            DETAILS="$DETAILS\nCGI 매핑: [ACTIVE] 활성화됨"
        fi

        # 결과 판정 (주석 제거 후 활성화된 설정 기준)
        if [ -z "$CGI_SERVLET_ACTIVE" ] && [ -z "$CGI_MAPPING_ACTIVE" ]; then
            RES="Y"
            DESC="CGI 실행이 제한되어 있음 (설정 없음 또는 주석 처리됨)"
            DT="$DETAILS"
        else
            RES="M"
            DESC="CGI 설정이 활성화되어 있음 (확인 필요)"
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

    if [ -z "$SERVER_XML" ] || [ ! -f "$SERVER_XML" ]; then
        RES="N/A"
        DESC="server.xml 파일을 찾을 수 없음"
        DT="SERVER_XML: not found"
    else
        # allowLinking 설정 확인 (Context 요소에서) - 줄번호 포함
        local ALLOW_LINKING=$(grep -n -i "allowLinking" "$SERVER_XML" 2>/dev/null | grep -v "^\s*<!--")

        # context.xml에서도 확인
        local CONTEXT_LINKING=""
        if [ -f "$CONTEXT_XML" ]; then
            CONTEXT_LINKING=$(grep -n -i "allowLinking" "$CONTEXT_XML" 2>/dev/null | grep -v "^\s*<!--")
        fi

        # allowLinking=true 설정이 있는지 확인
        local LINKING_TRUE=""
        [ -n "$ALLOW_LINKING" ] && LINKING_TRUE=$(echo "$ALLOW_LINKING" | grep -i "true")
        local CONTEXT_TRUE=""
        [ -n "$CONTEXT_LINKING" ] && CONTEXT_TRUE=$(echo "$CONTEXT_LINKING" | grep -i "true")

        if [ -n "$LINKING_TRUE" ] || [ -n "$CONTEXT_TRUE" ]; then
            RES="N"
            DESC="상위 디렉터리 접근이 허용되어 있음 (allowLinking=true)"
            local DETAILS=""
            [ -n "$LINKING_TRUE" ] && DETAILS="$SERVER_XML:\n$LINKING_TRUE"
            [ -n "$CONTEXT_TRUE" ] && DETAILS="${DETAILS:+$DETAILS\n}$CONTEXT_XML:\n$CONTEXT_TRUE"
            DT="$DETAILS"
        elif [ -n "$ALLOW_LINKING" ] || [ -n "$CONTEXT_LINKING" ]; then
            RES="Y"
            DESC="allowLinking이 false로 설정되어 있어 양호함"
            local DETAILS=""
            [ -n "$ALLOW_LINKING" ] && DETAILS="$SERVER_XML:\n$ALLOW_LINKING"
            [ -n "$CONTEXT_LINKING" ] && DETAILS="${DETAILS:+$DETAILS\n}$CONTEXT_XML:\n$CONTEXT_LINKING"
            DT="$DETAILS"
        else
            RES="Y"
            DESC="allowLinking이 설정되어 있지 않아 기본값(false)으로 양호함"
            DT="allowLinking: 미설정 (기본값 false)"
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

    if [ -z "$CATALINA_HOME" ]; then
        RES="N/A"
        DESC="Tomcat 설치 경로를 찾을 수 없음"
        DT="CATALINA_HOME: not found"
    else
        local WEBAPPS="${CATALINA_HOME}/webapps"
        local FOUND_ITEMS=""

        # 불필요한 기본 애플리케이션 확인
        local UNNECESSARY_APPS=("docs" "examples" "host-manager" "manager")
        for app in "${UNNECESSARY_APPS[@]}"; do
            if [ -d "${WEBAPPS}/${app}" ]; then
                FOUND_ITEMS="$FOUND_ITEMS\n- ${WEBAPPS}/${app}"
            fi
        done

        # 불필요한 파일 확인
        local UNNECESSARY_FILES=$(find "$WEBAPPS" -type f \( -name "*.bak" -o -name "*.backup" -o -name "*.old" -o -name "*.tmp" -o -name "BUILDING.txt" -o -name "RELEASE-NOTES.txt" -o -name "README.txt" \) 2>/dev/null | head -10)

        if [ -z "$FOUND_ITEMS" ] && [ -z "$UNNECESSARY_FILES" ]; then
            RES="Y"
            DESC="불필요한 파일 및 디렉터리가 없음"
            DT="기본 애플리케이션: 제거됨\n불필요 파일: 없음"
        else
            RES="N"
            DESC="불필요한 파일 또는 디렉터리가 존재함"
            DT="기본 애플리케이션:$FOUND_ITEMS\n불필요 파일:\n$UNNECESSARY_FILES"
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

    if [ -z "$SERVER_XML" ] || [ ! -f "$SERVER_XML" ]; then
        RES="N/A"
        DESC="server.xml 파일을 찾을 수 없음"
        DT="SERVER_XML: not found"
    else
        # maxPostSize 설정 확인 (줄번호 포함)
        local MAX_POST_LINE=$(grep -n -i 'maxPostSize' "$SERVER_XML" 2>/dev/null | grep -v "^\s*<!--" | head -1)
        local MAX_POST_SIZE=$(echo "$MAX_POST_LINE" | grep -oP 'maxPostSize\s*=\s*"\K[^"]+' 2>/dev/null)
        local MAX_POST_LINENUM=$(echo "$MAX_POST_LINE" | cut -d: -f1)

        # web.xml에서 multipart-config 확인 (줄번호 포함)
        local MULTIPART_CONFIG=""
        local MULTIPART_LINENUM=""
        if [ -f "$WEB_XML" ]; then
            MULTIPART_LINENUM=$(grep -n "<multipart-config>" "$WEB_XML" 2>/dev/null | grep -v "^\s*<!--" | head -1 | cut -d: -f1)
            if [ -n "$MULTIPART_LINENUM" ]; then
                MULTIPART_CONFIG=$(grep -A10 "<multipart-config>" "$WEB_XML" 2>/dev/null | head -15)
            fi
        fi

        local DETAILS=""
        if [ -n "$MAX_POST_SIZE" ]; then
            DETAILS="maxPostSize: $MAX_POST_SIZE\n  설정파일: $SERVER_XML:$MAX_POST_LINENUM"
        else
            DETAILS="maxPostSize: 미설정 (기본값: 2MB)"
        fi

        if [ -n "$MULTIPART_CONFIG" ]; then
            DETAILS="$DETAILS\nmultipart-config:\n  설정파일: $WEB_XML:$MULTIPART_LINENUM\n$MULTIPART_CONFIG"
        else
            DETAILS="$DETAILS\nmultipart-config: 미설정"
        fi

        if [ -n "$MAX_POST_SIZE" ] || [ -n "$MULTIPART_CONFIG" ]; then
            RES="M"
            DESC="파일 업로드 용량 제한이 설정됨 - 적절성 수동 확인 필요"
            DT="$DETAILS"
        else
            RES="N"
            DESC="파일 업로드 용량 제한이 설정되지 않음"
            DT="$DETAILS"
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

    # Tomcat 프로세스 실행 계정 확인
    local TOMCAT_USER=$(ps aux 2>/dev/null | grep -E "(catalina|tomcat)" | grep -v grep | grep -v root | awk '{print $1}' | sort -u | head -1)

    # systemd 서비스 파일에서 User 확인
    local SERVICE_USER=""
    if [ -f "/etc/systemd/system/tomcat.service" ]; then
        SERVICE_USER=$(grep "^User=" /etc/systemd/system/tomcat.service 2>/dev/null | cut -d'=' -f2)
    elif [ -f "/usr/lib/systemd/system/tomcat.service" ]; then
        SERVICE_USER=$(grep "^User=" /usr/lib/systemd/system/tomcat.service 2>/dev/null | cut -d'=' -f2)
    fi

    # root로 실행 중인지 확인
    local ROOT_PROC=$(ps aux 2>/dev/null | grep -E "(catalina|tomcat)" | grep -v grep | grep "^root" | head -1)

    local CHECK_USER="${TOMCAT_USER:-$SERVICE_USER}"

    if [ -z "$CHECK_USER" ] && [ -z "$ROOT_PROC" ]; then
        RES="M"
        DESC="Tomcat 프로세스를 확인할 수 없음"
        DT="실행 중인 프로세스: 없음\n서비스 파일 User: ${SERVICE_USER:-미설정}"
    elif [ -n "$ROOT_PROC" ]; then
        RES="N"
        DESC="Tomcat이 root 권한으로 실행 중"
        local PROC_DETAIL=$(ps aux 2>/dev/null | grep -E "(catalina|tomcat)" | grep -v grep | grep "^root")
        DT="실행 계정: root\n\n[프로세스 상세]\n$PROC_DETAIL"
    else
        RES="Y"
        DESC="Tomcat이 제한된 권한으로 실행 중"
        local PROC_DETAIL=$(ps aux 2>/dev/null | grep -E "(catalina|tomcat)" | grep -v grep)
        DT="실행 계정: $CHECK_USER\n서비스 파일 User: ${SERVICE_USER:-미설정}\n\n[프로세스 상세]\n$PROC_DETAIL"
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

    if [ -z "$SERVER_XML" ] || [ ! -f "$SERVER_XML" ]; then
        RES="N/A"
        DESC="server.xml 파일을 찾을 수 없음"
        DT="SERVER_XML: not found"
    else
        # proxyName, proxyPort 설정 확인
        local PROXY_NAME=$(grep -i "proxyName" "$SERVER_XML" 2>/dev/null | grep -v "^\s*<!--")
        local PROXY_PORT=$(grep -i "proxyPort" "$SERVER_XML" 2>/dev/null | grep -v "^\s*<!--")

        if [ -z "$PROXY_NAME" ] && [ -z "$PROXY_PORT" ]; then
            RES="Y"
            DESC="프록시 설정이 없음"
            DT="proxyName: 미설정\nproxyPort: 미설정"
        else
            RES="M"
            DESC="프록시 설정 확인 필요 (리버스 프록시 사용 시 양호)"
            local DETAILS=""
            [ -n "$PROXY_NAME" ] && DETAILS="proxyName:\n$PROXY_NAME"
            [ -n "$PROXY_PORT" ] && DETAILS="$DETAILS\nproxyPort:\n$PROXY_PORT"
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

    if [ -z "$SERVER_XML" ] || [ ! -f "$SERVER_XML" ]; then
        RES="N/A"
        DESC="server.xml 파일을 찾을 수 없음"
        DT="SERVER_XML: not found"
    else
        # docBase, appBase 설정 확인
        local DOC_BASE=$(grep -oP 'docBase\s*=\s*"\K[^"]+' "$SERVER_XML" 2>/dev/null | head -1)
        local APP_BASE=$(grep -oP 'appBase\s*=\s*"\K[^"]+' "$SERVER_XML" 2>/dev/null | head -1)

        local DEFAULT_PATHS=("webapps" "ROOT")
        local IS_DEFAULT="N"

        for path in "${DEFAULT_PATHS[@]}"; do
            if [ "$DOC_BASE" = "$path" ] || [ "$APP_BASE" = "$path" ]; then
                IS_DEFAULT="Y"
                break
            fi
        done

        if [ -z "$DOC_BASE" ] && [ "$APP_BASE" = "webapps" ]; then
            RES="M"
            DESC="기본 appBase 경로 사용 중 (수동 확인 필요)"
            DT="appBase: $APP_BASE (기본 경로)"
        elif [ -n "$DOC_BASE" ] && [ "$IS_DEFAULT" = "N" ]; then
            RES="Y"
            DESC="별도의 문서 경로가 설정됨"
            DT="docBase: $DOC_BASE\nappBase: ${APP_BASE:-webapps}"
        else
            RES="M"
            DESC="웹 서비스 경로 수동 확인 필요"
            DT="docBase: ${DOC_BASE:-미설정}\nappBase: ${APP_BASE:-webapps}"
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

    if [ -z "$SERVER_XML" ] || [ ! -f "$SERVER_XML" ]; then
        RES="N/A"
        DESC="server.xml 파일을 찾을 수 없음"
        DT="SERVER_XML: not found"
    else
        # allowLinking 설정 확인 - 줄번호 포함
        local ALLOW_LINKING=$(grep -n -i "allowLinking" "$SERVER_XML" 2>/dev/null | grep -v "^\s*<!--")

        # context.xml에서도 확인
        local CONTEXT_LINKING=""
        if [ -f "$CONTEXT_XML" ]; then
            CONTEXT_LINKING=$(grep -n -i "allowLinking" "$CONTEXT_XML" 2>/dev/null | grep -v "^\s*<!--")
        fi

        # allowLinking=true 설정이 있는지 확인
        local LINKING_TRUE=""
        [ -n "$ALLOW_LINKING" ] && LINKING_TRUE=$(echo "$ALLOW_LINKING" | grep -i "true")
        local CONTEXT_TRUE=""
        [ -n "$CONTEXT_LINKING" ] && CONTEXT_TRUE=$(echo "$CONTEXT_LINKING" | grep -i "true")

        if [ -n "$LINKING_TRUE" ] || [ -n "$CONTEXT_TRUE" ]; then
            RES="N"
            DESC="심볼릭 링크 사용이 허용되어 있음 (allowLinking=true)"
            local DETAILS=""
            [ -n "$LINKING_TRUE" ] && DETAILS="$SERVER_XML:\n$LINKING_TRUE"
            [ -n "$CONTEXT_TRUE" ] && DETAILS="${DETAILS:+$DETAILS\n}$CONTEXT_XML:\n$CONTEXT_TRUE"
            DT="$DETAILS"
        elif [ -n "$ALLOW_LINKING" ] || [ -n "$CONTEXT_LINKING" ]; then
            RES="Y"
            DESC="allowLinking이 false로 설정되어 있어 양호함"
            local DETAILS=""
            [ -n "$ALLOW_LINKING" ] && DETAILS="$SERVER_XML:\n$ALLOW_LINKING"
            [ -n "$CONTEXT_LINKING" ] && DETAILS="${DETAILS:+$DETAILS\n}$CONTEXT_XML:\n$CONTEXT_LINKING"
            DT="$DETAILS"
        else
            RES="Y"
            DESC="allowLinking이 설정되어 있지 않아 기본값(false)으로 양호함"
            DT="allowLinking: 미설정 (기본값 false)"
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

    if [ -z "$TOMCAT_CONF" ] || [ ! -d "$TOMCAT_CONF" ]; then
        RES="N/A"
        DESC="Tomcat 설정 디렉터리를 찾을 수 없음"
        DT="TOMCAT_CONF: not found"
    else
        local ISSUES=""
        local HAS_ISSUE="N"

        # server.xml 권한 확인
        if [ -f "$SERVER_XML" ]; then
            local SERVER_PERM=$(stat -c "%a" "$SERVER_XML" 2>/dev/null)
            local OTHER_PERM=${SERVER_PERM: -1}
            if [ "$OTHER_PERM" -ne 0 ]; then
                HAS_ISSUE="Y"
                ISSUES="$ISSUES\nserver.xml: 권한 $SERVER_PERM (other 접근 가능)"
            fi
        fi

        # web.xml 권한 확인
        if [ -f "$WEB_XML" ]; then
            local WEB_PERM=$(stat -c "%a" "$WEB_XML" 2>/dev/null)
            local OTHER_PERM=${WEB_PERM: -1}
            if [ "$OTHER_PERM" -ne 0 ]; then
                HAS_ISSUE="Y"
                ISSUES="$ISSUES\nweb.xml: 권한 $WEB_PERM (other 접근 가능)"
            fi
        fi

        # JDBC 연결 정보 확인
        local JDBC_INFO=$(grep -i "jdbc\|DataSource\|password" "$SERVER_XML" 2>/dev/null | grep -v "^\s*<!--" | head -5)
        if [ -n "$JDBC_INFO" ]; then
            ISSUES="$ISSUES\nDB 연결 정보 존재 (권한 확인 필요)"
        fi

        if [ "$HAS_ISSUE" = "N" ]; then
            RES="Y"
            DESC="설정 파일 접근 권한이 적절하게 설정됨"
            local SERVER_PERM_SHOW=$(stat -c "%a" "$SERVER_XML" 2>/dev/null)
            local SERVER_OWNER=$(stat -c "%U:%G" "$SERVER_XML" 2>/dev/null)
            local WEB_PERM_SHOW=$(stat -c "%a" "$WEB_XML" 2>/dev/null)
            local WEB_OWNER=$(stat -c "%U:%G" "$WEB_XML" 2>/dev/null)
            DT="$SERVER_XML - 권한: ${SERVER_PERM_SHOW:-N/A}, 소유자: ${SERVER_OWNER:-N/A}\n$WEB_XML - 권한: ${WEB_PERM_SHOW:-N/A}, 소유자: ${WEB_OWNER:-N/A}"
        else
            RES="N"
            DESC="설정 파일 접근 권한 조정 필요"
            DT="$ISSUES"
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

    if [ -z "$WEB_XML" ] || [ ! -f "$WEB_XML" ]; then
        RES="N/A"
        DESC="web.xml 파일을 찾을 수 없음"
        DT="WEB_XML: not found"
    else
        local FILE_PERM=$(stat -c "%a" "$WEB_XML" 2>/dev/null)
        local FILE_OWNER=$(stat -c "%U:%G" "$WEB_XML" 2>/dev/null)

        local OTHER_PERM=${FILE_PERM: -1}

        if [ "$OTHER_PERM" -eq 0 ]; then
            RES="Y"
            DESC="설정 파일에 적절한 권한이 설정됨"
            DT="$WEB_XML\n권한: $FILE_PERM\n소유자: $FILE_OWNER"
        else
            RES="N"
            DESC="설정 파일에 일반 사용자 접근 권한이 있음"
            DT="$WEB_XML\n권한: $FILE_PERM (other 권한 제거 필요)\n소유자: $FILE_OWNER"
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

    if [ -z "$WEB_XML" ] || [ ! -f "$WEB_XML" ]; then
        RES="N/A"
        DESC="web.xml 파일을 찾을 수 없음"
        DT="WEB_XML: not found"
    else
        # 주석 제거 후 XML 내용 추출
        local CLEANED_CONTENT=$(remove_xml_comments "$WEB_XML")

        # 기본 서블릿 외의 매핑 확인 (주석 제거된 내용에서)
        local UNNECESSARY_SERVLETS=""
        local DETAILS=""

        # invoker 서블릿 확인 (보안 취약)
        local INVOKER_STATUS=$(check_comment_status "$WEB_XML" "invoker")
        local INVOKER_ACTIVE=$(echo "$CLEANED_CONTENT" | grep -i "invoker" 2>/dev/null)
        if [ "$INVOKER_STATUS" = "COMMENTED" ]; then
            DETAILS="$DETAILS\ninvoker 서블릿: [COMMENTED] 주석 처리됨"
        elif [ -n "$INVOKER_ACTIVE" ]; then
            UNNECESSARY_SERVLETS="$UNNECESSARY_SERVLETS\ninvoker 서블릿: [ACTIVE] 활성화됨"
            DETAILS="$DETAILS\ninvoker 서블릿: [ACTIVE] 활성화됨"
        else
            DETAILS="$DETAILS\ninvoker 서블릿: 미설정"
        fi

        # SSI 서블릿 확인
        local SSI_STATUS=$(check_comment_status "$WEB_XML" "SSIServlet\|SSIFilter")
        local SSI_ACTIVE=$(echo "$CLEANED_CONTENT" | grep -iE "SSIServlet|SSIFilter" 2>/dev/null)
        if [ "$SSI_STATUS" = "COMMENTED" ]; then
            DETAILS="$DETAILS\nSSI 서블릿/필터: [COMMENTED] 주석 처리됨"
        elif [ -n "$SSI_ACTIVE" ]; then
            UNNECESSARY_SERVLETS="$UNNECESSARY_SERVLETS\nSSI 서블릿/필터: [ACTIVE] 활성화됨"
            DETAILS="$DETAILS\nSSI 서블릿/필터: [ACTIVE] 활성화됨"
        else
            DETAILS="$DETAILS\nSSI 서블릿/필터: 미설정"
        fi

        # CGI 서블릿 확인
        local CGI_STATUS=$(check_comment_status "$WEB_XML" "CGIServlet")
        local CGI_ACTIVE=$(echo "$CLEANED_CONTENT" | grep -i "CGIServlet" 2>/dev/null)
        if [ "$CGI_STATUS" = "COMMENTED" ]; then
            DETAILS="$DETAILS\nCGI 서블릿: [COMMENTED] 주석 처리됨"
        elif [ -n "$CGI_ACTIVE" ]; then
            UNNECESSARY_SERVLETS="$UNNECESSARY_SERVLETS\nCGI 서블릿: [ACTIVE] 활성화됨"
            DETAILS="$DETAILS\nCGI 서블릿: [ACTIVE] 활성화됨"
        else
            DETAILS="$DETAILS\nCGI 서블릿: 미설정"
        fi

        if [ -z "$UNNECESSARY_SERVLETS" ]; then
            RES="Y"
            DESC="불필요한 스크립트 매핑이 없음 (활성화된 설정 없음)"
            DT="$DETAILS"
        else
            RES="N"
            DESC="불필요한 스크립트 매핑이 활성화되어 있음"
            DT="$DETAILS"
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

    if [ -z "$SERVER_XML" ] || [ ! -f "$SERVER_XML" ]; then
        RES="N/A"
        DESC="server.xml 파일을 찾을 수 없음"
        DT="SERVER_XML: not found"
    else
        # server 속성 확인 (Connector에서) - 줄번호 포함
        local SERVER_ATTR_LINE=$(grep -n -i 'server\s*=' "$SERVER_XML" 2>/dev/null | grep -i "Connector" | grep -v "^\s*<!--" | head -1)
        local SERVER_ATTR=$(echo "$SERVER_ATTR_LINE" | grep -oP 'server\s*=\s*"\K[^"]+' 2>/dev/null)
        local SERVER_ATTR_LINENUM=$(echo "$SERVER_ATTR_LINE" | cut -d: -f1)

        # ErrorReportValve의 showServerInfo 확인 - 줄번호 포함
        local SHOW_SERVER_LINE=$(grep -n -i "showServerInfo" "$SERVER_XML" 2>/dev/null | grep -v "^\s*<!--" | head -1)
        local SERVER_INFO_FALSE=$(echo "$SHOW_SERVER_LINE" | grep -i "false")
        local SHOW_SERVER_LINENUM=$(echo "$SHOW_SERVER_LINE" | cut -d: -f1)

        local IS_SECURE="Y"
        local ISSUES=""
        local DESC_DETAIL=""

        if [ -z "$SERVER_ATTR" ]; then
            IS_SECURE="N"
            DESC_DETAIL="Connector server 속성이 미설정되어 기본 서버 정보가 노출되고 있어 취약함"
            ISSUES="Connector server 속성: 미설정 (기본 정보 노출)"
        else
            ISSUES="Connector server 속성: $SERVER_ATTR\n  설정파일: $SERVER_XML:$SERVER_ATTR_LINENUM"
        fi

        if [ -z "$SERVER_INFO_FALSE" ]; then
            IS_SECURE="N"
            if [ -n "$DESC_DETAIL" ]; then
                DESC_DETAIL="${DESC_DETAIL}, showServerInfo가 false로 설정되지 않아 에러 페이지에서 서버 정보가 노출됨"
            else
                DESC_DETAIL="showServerInfo가 false로 설정되지 않아 에러 페이지에서 서버 정보가 노출될 수 있어 취약함"
            fi
            ISSUES="${ISSUES:+$ISSUES\n}showServerInfo: false 미설정"
        else
            ISSUES="${ISSUES:+$ISSUES\n}showServerInfo: false\n  설정파일: $SERVER_XML:$SHOW_SERVER_LINENUM"
        fi

        if [ "$IS_SECURE" = "Y" ]; then
            RES="Y"
            DESC="서버 헤더 정보 노출이 제한됨"
            DT="$ISSUES"
        else
            RES="N"
            DESC="$DESC_DETAIL"
            DT="$ISSUES"
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

    if [ -z "$SERVER_XML" ] || [ ! -f "$SERVER_XML" ]; then
        RES="N/A"
        DESC="server.xml 파일을 찾을 수 없음"
        DT="SERVER_XML: not found"
    else
        # Context path 설정 확인
        local CONTEXTS=$(grep -E "<Context\s+.*path\s*=" "$SERVER_XML" 2>/dev/null | grep -v "^\s*<!--")

        if [ -z "$CONTEXTS" ]; then
            RES="Y"
            DESC="추가 가상 디렉터리 설정이 없음"
            DT="Context path: 미설정"
        else
            RES="M"
            DESC="가상 디렉터리 설정 확인 필요"
            DT="Context 설정:\n$CONTEXTS"
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

    local RES="N/A"
    local DESC="Tomcat은 기본적으로 WebDAV를 지원하지 않음 (별도 설정 필요)"
    local DT="Tomcat은 Apache HTTP Server와 달리 WebDAV 모듈이 기본 내장되어 있지 않습니다.\n별도의 WebDAV 서블릿 구성이 필요하므로 해당 항목은 N/A 처리합니다."

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

    if [ -z "$WEB_XML" ] || [ ! -f "$WEB_XML" ]; then
        RES="N/A"
        DESC="web.xml 파일을 찾을 수 없음"
        DT="WEB_XML: not found"
    else
        # 주석 제거 후 XML 내용 추출
        local CLEANED_CONTENT=$(remove_xml_comments "$WEB_XML")

        # SSI 서블릿 주석 상태 확인
        local SSI_SERVLET_STATUS=$(check_comment_status "$WEB_XML" "SSIServlet")
        local SSI_FILTER_STATUS=$(check_comment_status "$WEB_XML" "SSIFilter")
        local SSI_MAPPING_STATUS=$(check_comment_status "$WEB_XML" "\.shtml")

        # 주석 제거된 내용에서 SSI 설정 확인
        local SSI_SERVLET_ACTIVE=$(echo "$CLEANED_CONTENT" | grep -i "SSIServlet" 2>/dev/null)
        local SSI_FILTER_ACTIVE=$(echo "$CLEANED_CONTENT" | grep -i "SSIFilter" 2>/dev/null)
        local SSI_MAPPING_ACTIVE=$(echo "$CLEANED_CONTENT" | grep -i "\.shtml" 2>/dev/null)

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

        # 결과 판정 (주석 제거 후 활성화된 설정 기준)
        if [ "$HAS_ACTIVE" = "N" ]; then
            RES="Y"
            DESC="SSI가 비활성화되어 있음 (설정 없음 또는 주석 처리됨)"
            DT="$DETAILS"
        else
            RES="N"
            DESC="SSI가 활성화되어 있음"
            DT="$DETAILS"
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

    local RES="N/A"
    local DESC="Tomcat 앞단에 웹서버(Apache/Nginx)를 두고 SSL 처리 권장"
    local DT="일반적으로 Tomcat 앞단에 Apache HTTP Server 또는 Nginx를 리버스 프록시로 배치하여\nSSL/TLS 처리를 위임하는 구성을 권장합니다.\n\n직접 Tomcat에서 SSL을 처리할 경우 server.xml의 Connector에서 설정하며,\n이 경우 별도 점검이 필요합니다."

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
    local DESC="Tomcat 앞단 웹서버에서 HTTPS 리디렉션 처리 권장"
    local DT="HTTP에서 HTTPS로의 리디렉션은 일반적으로 앞단 웹서버(Apache/Nginx)에서 처리합니다.\n\nTomcat 단독 구성 시 web.xml의 security-constraint를 통해 HTTPS 강제 가능하나,\n앞단 웹서버 사용 환경에서는 해당 웹서버 설정을 점검해야 합니다."

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

    if [ -z "$WEB_XML" ] || [ ! -f "$WEB_XML" ]; then
        RES="N/A"
        DESC="web.xml 파일을 찾을 수 없음"
        DT="WEB_XML: not found"
    else
        # error-page 설정 확인 (줄번호 포함)
        local ERROR_PAGE_LINES=$(grep -n "<error-page>\|<error-code>\|<location>" "$WEB_XML" 2>/dev/null | grep -v "^\s*<!--")
        local ERROR_PAGES=$(grep -A5 "<error-page>" "$WEB_XML" 2>/dev/null | grep -v "^\s*<!--" | head -30)

        if [ -n "$ERROR_PAGES" ]; then
            # 주요 오류 코드 필수 설정 확인 (400, 401, 403, 404, 500)
            local ERROR_CODES=$(grep -oP '<error-code>\K[0-9]+' "$WEB_XML" 2>/dev/null)
            local REQUIRED_CODES="400 401 403 404 500"
            local MISSING_CODES=""
            for code in $REQUIRED_CODES; do
                if ! echo "$ERROR_CODES" | grep -q "^${code}$"; then
                    MISSING_CODES="$MISSING_CODES $code"
                fi
            done

            if [ -z "$MISSING_CODES" ]; then
                RES="Y"
                DESC="주요 에러 코드(400,401,403,404,500)에 대한 에러 페이지가 설정되어 있음"
                DT="error-page 설정 ($WEB_XML):\n$ERROR_PAGES"
            else
                RES="N"
                DESC="주요 에러 코드 중 일부에 대한 에러 페이지가 미설정됨"
                DT="error-page 설정 ($WEB_XML):\n$ERROR_PAGES\n\n[취약] 미설정 에러 코드:$MISSING_CODES\n필수 에러 코드(400,401,403,404,500)에 대한 error-page 설정이 필요합니다."
            fi
        else
            RES="N"
            DESC="에러 페이지가 설정되지 않음"
            DT="error-page: 미설정 (기본 에러 페이지 사용)\n설정파일: $WEB_XML\n\n[취약] 필수 에러 코드(400,401,403,404,500)에 대한 error-page 설정이 필요합니다."
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

    if [ -z "$SERVER_XML" ] || [ ! -f "$SERVER_XML" ]; then
        RES="N/A"
        DESC="server.xml 파일을 찾을 수 없음"
        DT="SERVER_XML: not found"
    else
        # LDAP Realm 설정 확인
        local LDAP_REALM=$(grep -i "JNDIRealm\|LDAPRealm" "$SERVER_XML" 2>/dev/null | grep -v "^\s*<!--")

        if [ -z "$LDAP_REALM" ]; then
            RES="N/A"
            DESC="LDAP Realm이 설정되지 않음"
            DT="LDAP Realm: 미사용"
        else
            # digest 속성 확인
            local DIGEST=$(grep -oP 'digest\s*=\s*"\K[^"]+' "$SERVER_XML" 2>/dev/null | head -1)

            if [ -z "$DIGEST" ]; then
                RES="N"
                DESC="LDAP 비밀번호 다이제스트 알고리즘이 설정되지 않음"
                DT="LDAP Realm 사용 중\ndigest: 미설정 (평문 전송)"
            elif echo "$DIGEST" | grep -qiE "^(SHA-256|SHA-384|SHA-512|SHA256|SHA384|SHA512)"; then
                RES="Y"
                DESC="안전한 다이제스트 알고리즘 사용 중"
                DT="digest: $DIGEST"
            elif echo "$DIGEST" | grep -qiE "^(MD5|SHA-1|SHA1|SSHA)"; then
                RES="N"
                DESC="취약한 다이제스트 알고리즘 사용 중"
                DT="digest: $DIGEST (SHA-256 이상 권장)"
            else
                RES="M"
                DESC="다이제스트 알고리즘 수동 확인 필요"
                DT="digest: $DIGEST"
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

    # 일반적인 Tomcat 업로드 디렉터리 확인
    local UPLOAD_PATHS=(
        "${CATALINA_HOME}/webapps/uploads"
        "${CATALINA_HOME}/webapps/ROOT/uploads"
        "/var/www/html/uploads"
        "/var/uploads"
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

    # Tomcat 버전 확인
    local VERSION=""
    if [ -n "$CATALINA_HOME" ] && [ -f "$CATALINA_HOME/lib/catalina.jar" ]; then
        VERSION=$(java -cp "$CATALINA_HOME/lib/catalina.jar" org.apache.catalina.util.ServerInfo 2>/dev/null)
    fi

    if [ -z "$VERSION" ]; then
        # 다른 방법으로 버전 확인
        if [ -f "${CATALINA_HOME}/RELEASE-NOTES" ]; then
            VERSION=$(head -5 "${CATALINA_HOME}/RELEASE-NOTES" 2>/dev/null | grep -i "version\|tomcat")
        fi
    fi

    if [ -z "$VERSION" ]; then
        RES="M"
        DESC="Tomcat 버전을 확인할 수 없음"
        DT="catalina.jar 또는 RELEASE-NOTES를 찾을 수 없음"
    else
        RES="M"
        DESC="버전 정보 확인 (수동 패치 확인 필요)"
        DT="$VERSION\n\n최신 버전 확인: https://tomcat.apache.org/"
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
    local LOG_DIR="${CATALINA_HOME}/logs"

    if [ -z "$CATALINA_HOME" ] || [ ! -d "$LOG_DIR" ]; then
        # 일반적인 로그 경로 확인
        local LOG_PATHS=(
            "/var/log/tomcat"
            "/var/log/tomcat9"
            "/var/log/tomcat8"
            "/opt/tomcat/logs"
        )
        for path in "${LOG_PATHS[@]}"; do
            if [ -d "$path" ]; then
                LOG_DIR="$path"
                break
            fi
        done
    fi

    if [ -z "$LOG_DIR" ] || [ ! -d "$LOG_DIR" ]; then
        RES="M"
        DESC="로그 디렉터리를 찾을 수 없음 (수동 확인 필요)"
        DT="일반적인 경로에 로그 디렉터리 없음"
    else
        local DIR_PERM=$(stat -c "%a" "$LOG_DIR" 2>/dev/null)
        local DIR_OWNER=$(stat -c "%U:%G" "$LOG_DIR" 2>/dev/null)
        local OTHER_PERM=${DIR_PERM: -1}

        # 로그 파일 권한 확인
        local LOG_FILES=$(find "$LOG_DIR" -type f -name "*.log" 2>/dev/null | head -3)
        local FILE_PERMS=""
        for f in $LOG_FILES; do
            local F_PERM=$(stat -c "%a %n" "$f" 2>/dev/null)
            FILE_PERMS="$FILE_PERMS\n$F_PERM"
        done

        if [ "$OTHER_PERM" -eq 0 ]; then
            RES="Y"
            DESC="로그 디렉터리에 적절한 권한이 설정됨"
            DT="$LOG_DIR - 권한: $DIR_PERM, 소유자: $DIR_OWNER\n로그 파일:$FILE_PERMS"
        else
            RES="N"
            DESC="로그 디렉터리에 일반 사용자 접근 권한이 있음"
            DT="$LOG_DIR - 권한: $DIR_PERM (other 권한 제거 필요)\n소유자: $DIR_OWNER\n로그 파일:$FILE_PERMS"
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
