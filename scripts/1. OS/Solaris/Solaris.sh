#!/bin/ksh
#================================================================
# Solaris 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : Solaris 10, 11
# 항목  : U-01 ~ U-67 (67개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="Solaris"
META_TYPE="Server"

# 권한 체크
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] root 권한으로 실행하세요."
    exit 1
fi

# XML 특수문자 이스케이프
xml_escape() {
    typeset s="$1"
    s=$(echo "$s" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
    echo "$s"
}

# 결과 출력 함수
output_checkpoint() {
    typeset CODE="$1"
    typeset CAT="$2"
    typeset NAME="$3"
    typeset IMP="$4"
    typeset STD="$5"
    typeset RES="$6"
    typeset DESC="$7"
    typeset DT="$8"

    # 콘솔 출력
    case "$RES" in
        "Y")   printf "    [[32mY[0m] %s %s
#================================================================
# Solaris 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : Solaris 10, 11
# 항목  : U-01 ~ U-67 (67개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="Solaris"
META_TYPE="Server"

# 권한 체크
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] root 권한으로 실행하세요."
    exit 1
fi

# XML 특수문자 이스케이프
xml_escape() {
    typeset s="$1"
    s=$(echo "$s" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
    echo "$s"
}

# 결과 출력 함수
output_checkpoint() {
    typeset CODE="$1"
    typeset CAT="$2"
    typeset NAME="$3"
    typeset IMP="$4"
    typeset STD="$5"
    typeset RES="$6"
    typeset DESC="$7"
    typeset DT="$8"

    # 콘솔 출력
    case "$RES" in
        "Y")   printf "    [\033[32mY\033[0m] %s %s\n" "$CODE" "$NAME" ;;
        "N")   printf "    [\033[31mN\033[0m] %s %s\n" "$CODE" "$NAME" ;;
        "M")   printf "    [\033[33mM\033[0m] %s %s\n" "$CODE" "$NAME" ;;
        "N/A") printf "    [\033[90m-\033[0m] %s %s\n" "$CODE" "$NAME" ;;
        *)     printf "    [-] %s %s\n" "$CODE" "$NAME" ;;
    esac

    # XML 출력
    typeset E_NAME; E_NAME=$(xml_escape "$NAME")
    typeset E_DESC; E_DESC=$(xml_escape "$DESC")
    typeset E_STD; E_STD=$(xml_escape "$STD")
    printf "        <cp>\n" >> "$OUTPUT_FILE"
    printf "            <code>%s</code>\n" "$CODE" >> "$OUTPUT_FILE"
    printf "            <cat>%s</cat>\n" "$CAT" >> "$OUTPUT_FILE"
    printf "            <n>%s</n>\n" "$E_NAME" >> "$OUTPUT_FILE"
    printf "            <imp>%s</imp>\n" "$IMP" >> "$OUTPUT_FILE"
    printf "            <std>%s</std>\n" "$E_STD" >> "$OUTPUT_FILE"
    printf "            <res>%s</res>\n" "$RES" >> "$OUTPUT_FILE"
    printf "            <desc>%s</desc>\n" "$E_DESC" >> "$OUTPUT_FILE"
    printf "            <dt><![CDATA[%s]]></dt>\n" "$DT" >> "$OUTPUT_FILE"
    printf "        </cp>\n" >> "$OUTPUT_FILE"
}

#================================================================
# POSIX 호환 유틸리티 함수
#================================================================

get_file_perm() {
    ls -ld "$1" 2>/dev/null | awk '{
        p=substr($1,2,9); m=0
        if(substr(p,1,1)=="r")m+=400; if(substr(p,2,1)=="w")m+=200; if(substr(p,3,1)~/[xsS]/)m+=100
        if(substr(p,4,1)=="r")m+=40;  if(substr(p,5,1)=="w")m+=20;  if(substr(p,6,1)~/[xsS]/)m+=10
        if(substr(p,7,1)=="r")m+=4;   if(substr(p,8,1)=="w")m+=2;   if(substr(p,9,1)~/[xtT]/)m+=1
        printf "%03d",m
    }'
}

get_file_owner() { ls -ld "$1" 2>/dev/null | awk '{print $3}'; }
get_file_group() { ls -ld "$1" 2>/dev/null | awk '{print $4}'; }
to_lower() { echo "$1" | tr 'A-Z' 'a-z'; }
to_upper() { echo "$1" | tr 'a-z' 'A-Z'; }

is_process_running() {
    ps -ef 2>/dev/null | grep -v grep | grep -q "$1"
}

matches_pattern() {
    typeset string="$1"; typeset pattern="$2"
    echo "$string" | grep -qE "$pattern"
}

contains_string() {
    typeset string="$1"; typeset substring="$2"
    case "$string" in *"$substring"*) return 0 ;; *) return 1 ;; esac
}

is_number() {
    case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac
}

#================================================================
# Solaris 플랫폼 헬퍼
#================================================================

# 서비스 실행 확인 (Solaris SMF)
is_service_running() {
    typeset service="$1"
    # SMF (Solaris 10+)
    if [ -x /usr/bin/svcs ]; then
        svcs -H "$service" 2>/dev/null | grep -q "online"
        return $?
    fi
    # 프로세스 확인 (fallback)
    ps -ef 2>/dev/null | grep -v grep | grep -q "$service"
}

# SMF 서비스 상태 확인
get_smf_state() {
    typeset fmri="$1"
    svcs -H -o state "$fmri" 2>/dev/null | head -1
}

# Solaris 설정 파일 경로
SSHD_CONFIG="/etc/ssh/sshd_config"
LOGIN_CONFIG="/etc/default/login"
PASSWD_CONFIG="/etc/default/passwd"
POLICY_CONFIG="/etc/security/policy.conf"
DFSTAB="/etc/dfs/dfstab"

#================================================================
# COLLECT — 시스템 정보 수집 (Solaris)
#================================================================

META_DATE=$(date +%Y-%m-%dT%H:%M:%S)
SYS_HOST=$(hostname)
SYS_DOM=$(domainname 2>/dev/null || echo "N/A")

# Solaris OS 정보
if [ -f /etc/release ]; then
    SYS_OS_NAME=$(head -1 /etc/release | sed 's/^[ \t]*//')
else
    SYS_OS_NAME="Solaris $(uname -r)"
fi
SYS_OS_FN="Solaris"
SYS_KN=$(uname -r)
SYS_ARCH=$(uname -p)

# Solaris IP 주소 수집
SYS_IP=$(ifconfig -a 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | awk '{print $2}' | head -1)
SYS_NET_ALL=$(ifconfig -a 2>/dev/null | awk '/^[a-z]/ {iface=$1} /inet / && !/127.0.0.1/ {gsub(/:$/,"",iface); print iface": "$2}')

# 출력 파일 경로
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
OUTPUT_FILE="${SCRIPT_DIR}/${META_PLAT}_${SYS_HOST}_$(date +%Y%m%d_%H%M%S).xml"

#================================================================
# CHECK FUNCTIONS
#================================================================

check01() {
    local CODE="U-01"
    local CAT="계정관리"
    local NAME="root 계정 원격 접속 제한"
    local IMP="상"
    local STD="원격터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset DETAILS=""
        typeset IS_SECURE="true"

        # SSH 설정 확인 (/etc/ssh/sshd_config)
        if [ -f "$SSHD_CONFIG" ]; then
            typeset PERMIT=$(grep -i "^PermitRootLogin" "$SSHD_CONFIG" 2>/dev/null | awk '{print $2}' | head -1)
            typeset PERMIT_LOWER=$(echo "$PERMIT" | tr 'A-Z' 'a-z')

            if [ "$PERMIT_LOWER" = "no" ]; then
                DETAILS="SSH PermitRootLogin: $PERMIT (양호)"
            elif [ -z "$PERMIT" ]; then
                IS_SECURE="false"
                DETAILS="SSH PermitRootLogin: not set (기본값 허용)"
            else
                IS_SECURE="false"
                DETAILS="SSH PermitRootLogin: $PERMIT (취약)"
            fi
        else
            DETAILS="SSH 설정 파일 없음 ($SSHD_CONFIG)"
        fi

        # Telnet 제한: /etc/default/login CONSOLE 설정 확인
        if [ -f "$LOGIN_CONFIG" ]; then
            typeset CONSOLE_VAL=$(grep "^CONSOLE" "$LOGIN_CONFIG" 2>/dev/null | cut -d'=' -f2)
            if [ -n "$CONSOLE_VAL" ]; then
                DETAILS="$DETAILS
    CONSOLE: $CONSOLE_VAL (양호)"
            else
                IS_SECURE="false"
                DETAILS="$DETAILS
    CONSOLE: not set (취약)"
            fi
        fi

        if [ "$IS_SECURE" = "true" ]; then
            RES="Y"
            DESC="root 원격 접속이 제한되어 있음"
        else
            RES="N"
            DESC="root 원격 접속이 허용되어 있음"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check02() {
    local CODE="U-02"
    local CAT="계정관리"
    local NAME="비밀번호 관리정책 설정"
    local IMP="상"
    local STD="비밀번호 관리 정책이 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset ISSUES=""
        typeset DETAILS=""
        typeset IS_OK="true"

        # /etc/default/passwd 파일 확인
        if [ -f "$PASSWD_CONFIG" ]; then
            typeset PASSLENGTH=$(grep "^PASSLENGTH" "$PASSWD_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
            typeset HISTORY=$(grep "^HISTORY" "$PASSWD_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
            typeset MINDIGIT=$(grep "^MINDIGIT" "$PASSWD_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
            typeset MINUPPER=$(grep "^MINUPPER" "$PASSWD_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
            typeset MINLOWER=$(grep "^MINLOWER" "$PASSWD_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
            typeset MINSPECIAL=$(grep "^MINSPECIAL" "$PASSWD_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')

            DETAILS="PASSLENGTH: ${PASSLENGTH:-not set}
    HISTORY: ${HISTORY:-not set}
    MINDIGIT: ${MINDIGIT:-not set}
    MINUPPER: ${MINUPPER:-not set}
    MINLOWER: ${MINLOWER:-not set}
    MINSPECIAL: ${MINSPECIAL:-not set}"

            # 최소 길이 점검
            if [ -z "$PASSLENGTH" ]; then
                IS_OK="false"
                ISSUES="${ISSUES}PASSLENGTH 미설정, "
            elif [ "$PASSLENGTH" -lt 8 ] 2>/dev/null; then
                IS_OK="false"
                ISSUES="${ISSUES}PASSLENGTH 8자 미만, "
            fi

            # 이력 관리 점검
            if [ -z "$HISTORY" ]; then
                IS_OK="false"
                ISSUES="${ISSUES}HISTORY 미설정, "
            elif [ "$HISTORY" -lt 4 ] 2>/dev/null; then
                IS_OK="false"
                ISSUES="${ISSUES}HISTORY 4회 미만, "
            fi

            # 복잡성 점검 (숫자)
            if [ -z "$MINDIGIT" ]; then
                IS_OK="false"
                ISSUES="${ISSUES}MINDIGIT 미설정, "
            fi

            # 복잡성 점검 (특수문자)
            if [ -z "$MINSPECIAL" ]; then
                IS_OK="false"
                ISSUES="${ISSUES}MINSPECIAL 미설정, "
            fi
        else
            IS_OK="false"
            DETAILS="$PASSWD_CONFIG 파일 없음"
            ISSUES="비밀번호 정책 파일 없음"
        fi

        if [ "$IS_OK" = "true" ]; then
            RES="Y"
            DESC="비밀번호 관리정책이 적절히 설정됨"
        else
            RES="N"
            DESC="비밀번호 관리정책 미흡 (${ISSUES%%, })"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check03() {
    local CODE="U-03"
    local CAT="계정관리"
    local NAME="계정 잠금 임계값 설정"
    local IMP="상"
    local STD="계정 잠금 임계값이 10회 이하의 값으로 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset DENY_VALUE=""
        typeset DETAILS=""

        # Solaris 5.9 이하: /etc/default/login RETRIES
        if [ -f "$LOGIN_CONFIG" ]; then
            typeset RETRIES=$(grep "^RETRIES" "$LOGIN_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
            if [ -n "$RETRIES" ]; then
                DENY_VALUE="$RETRIES"
                DETAILS="RETRIES (login): $RETRIES"
            fi
        fi

        # Solaris 5.9 이상: /etc/security/policy.conf LOCK_AFTER_RETRIES
        if [ -f "$POLICY_CONFIG" ]; then
            typeset LOCK_AFTER=$(grep "^LOCK_AFTER_RETRIES" "$POLICY_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
            if [ -n "$LOCK_AFTER" ]; then
                typeset LOCK_LOWER=$(echo "$LOCK_AFTER" | tr 'A-Z' 'a-z')
                if [ "$LOCK_LOWER" = "yes" ]; then
                    DENY_VALUE="enabled"
                    DETAILS="${DETAILS:+$DETAILS
    }LOCK_AFTER_RETRIES: $LOCK_AFTER (활성화)"
                else
                    DETAILS="${DETAILS:+$DETAILS
    }LOCK_AFTER_RETRIES: $LOCK_AFTER (비활성화)"
                fi
            fi
        fi

        # 판단
        if [ -z "$DENY_VALUE" ]; then
            RES="N"
            DESC="계정 잠금 임계값이 설정되지 않음"
            DT="RETRIES/LOCK_AFTER_RETRIES: not set"
        elif [ "$DENY_VALUE" = "enabled" ]; then
            RES="Y"
            DESC="계정 잠금 임계값이 적절히 설정됨"
            DT="$DETAILS"
        elif is_number "$DENY_VALUE" && [ "$DENY_VALUE" -le 10 ] 2>/dev/null; then
            RES="Y"
            DESC="계정 잠금 임계값이 적절히 설정됨"
            DT="$DETAILS"
        else
            RES="N"
            DESC="계정 잠금 임계값이 10회 초과"
            DT="$DETAILS (기준: 10회 이하)"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check04() {
    local CODE="U-04"
    local CAT="계정관리"
    local NAME="비밀번호 파일 보호"
    local IMP="상"
    local STD="쉐도우 비밀번호를 사용하거나, 비밀번호를 암호화하여 저장하는 경우"
    local RES=""
    local DESC=""
    local DT=""

        # /etc/passwd 두 번째 필드 확인 (x가 아닌 계정)
        typeset UNPROTECTED=$(awk -F: '$2 != "x" && $2 != "" {print $1}' /etc/passwd 2>/dev/null)

        # /etc/shadow 파일 존재 여부
        typeset SHADOW_EXISTS="N"
        if [ -f /etc/shadow ]; then
            SHADOW_EXISTS="Y"
        fi

        if [ -z "$UNPROTECTED" ] && [ "$SHADOW_EXISTS" = "Y" ]; then
            RES="Y"
            DESC="쉐도우 비밀번호를 사용하고 있음"
            DT="/etc/passwd 두 번째 필드: x
    /etc/shadow: 존재함"
        else
            typeset SHADOW_MSG="없음"
            if [ "$SHADOW_EXISTS" = "Y" ]; then
                SHADOW_MSG="존재함"
            fi
            RES="N"
            DESC="비밀번호 파일 보호 미흡"
            DT="쉐도우 미사용 계정: ${UNPROTECTED:-없음}
    /etc/shadow: $SHADOW_MSG"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check05() {
    local CODE="U-05"
    local CAT="계정관리"
    local NAME="root 이외의 UID가 ‘0’ 금지"
    local IMP="상"
    local STD="root 계정과 동일한 UID를 갖는 계정이 존재하지 않는 경우"
    local RES=""
    local DESC=""
    local DT=""

    # UID가 0인 계정 확인 (root 제외)
    typeset UID0_ACCOUNTS=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd 2>/dev/null)

    if [ -z "$UID0_ACCOUNTS" ]; then
        RES="Y"
        DESC="root 외 UID=0 계정이 존재하지 않음"
        DT="UID=0 계정: root만 존재"
    else
        RES="N"
        DESC="root 외 UID=0 계정이 존재함"
        DT="UID=0 계정: root, $UID0_ACCOUNTS"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check06() {
    local CODE="U-06"
    local CAT="계정관리"
    local NAME="사용자 계정 su 기능 제한"
    local IMP="상"
    local STD="su 명령어를 특정 그룹에 속한 사용자만 사용하도록 제한된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset DETAILS=""
        typeset IS_RESTRICTED="false"

        # wheel 그룹 확인
        typeset WHEEL_GROUP=$(grep "^wheel:" /etc/group 2>/dev/null)
        if [ -z "$WHEEL_GROUP" ]; then
            DETAILS="wheel 그룹: 없음"
        else
            DETAILS="wheel 그룹: $WHEEL_GROUP"
        fi

        # su 명령어 권한 및 그룹 확인
        typeset SU_PATH="/usr/bin/su"
        if [ -f "$SU_PATH" ]; then
            typeset SU_PERM=$(get_file_perm "$SU_PATH")
            typeset SU_GROUP=$(get_file_group "$SU_PATH")
            DETAILS="$DETAILS
    su 권한: $SU_PERM
    su 그룹: $SU_GROUP"

            # su가 wheel 그룹 소유이고 other에 실행 권한 없는 경우 (4750)
            if [ "$SU_GROUP" = "wheel" ]; then
                typeset OTHER_PERM=$((SU_PERM % 10))
                if [ "$OTHER_PERM" -eq 0 ]; then
                    IS_RESTRICTED="true"
                fi
            fi
        fi

        if [ "$IS_RESTRICTED" = "true" ]; then
            RES="Y"
            DESC="su 명령어가 특정 그룹에만 허용됨"
        else
            RES="N"
            DESC="su 명령어가 모든 사용자에게 허용됨"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check07() {
    local CODE="U-07"
    local CAT="계정관리"
    local NAME="불필요한 계정 제거"
    local IMP="하"
    local STD="불필요한 계정이 존재하지 않는 경우"
    local RES=""
    local DESC=""
    local DT=""

        # Solaris 기본 불필요 계정 목록
        typeset UNNECESSARY="lp uucp nuucp listen nobody4 noaccess diag"
        typeset FOUND_ACCOUNTS=""

        for acc in $UNNECESSARY; do
            if grep -q "^${acc}:" /etc/passwd 2>/dev/null; then
                typeset acc_shell=$(grep "^${acc}:" /etc/passwd 2>/dev/null | cut -d: -f7)
                case "$acc_shell" in
                    */nologin|*/false)
                        # nologin/false 쉘이면 제외
                        ;;
                    *)
                        FOUND_ACCOUNTS="${FOUND_ACCOUNTS}${acc} "
                        ;;
                esac
            fi
        done

        # 로그인 가능한 일반 계정 목록 (Solaris UID >= 100)
        typeset LOGIN_ACCOUNTS=$(awk -F: '$3 >= 100 && $7 !~ /nologin|false/ {print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ')

        if [ -z "$FOUND_ACCOUNTS" ]; then
            RES="M"
            DESC="불필요한 계정 수동 확인 필요"
            DT="확인된 불필요 계정: 없음
    로그인 가능 계정: ${LOGIN_ACCOUNTS:-없음}"
        else
            RES="N"
            DESC="불필요한 기본 계정이 존재함"
            DT="불필요 계정: $FOUND_ACCOUNTS"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check08() {
    local CODE="U-08"
    local CAT="계정관리"
    local NAME="관리자 그룹에 최소한의 계정 포함"
    local IMP="중"
    local STD="관리자 그룹에 불필요한 계정이 등록되어 있지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

        # root 그룹 (GID=0) 확인
        typeset ROOT_GROUP=$(grep "^root:" /etc/group 2>/dev/null)
        typeset ROOT_MEMBERS=$(echo "$ROOT_GROUP" | cut -d: -f4)

        if [ -z "$ROOT_MEMBERS" ]; then
            RES="Y"
            DESC="관리자 그룹에 추가 계정이 없음"
            DT="root 그룹: $ROOT_GROUP"
        else
            RES="M"
            DESC="관리자 그룹에 계정 존재, 수동 확인 필요"
            DT="root 그룹: $ROOT_GROUP
    그룹 멤버: $ROOT_MEMBERS"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check09() {
    local CODE="U-09"
    local CAT="계정관리"
    local NAME="계정이 존재하지 않는 GID 금지"
    local IMP="하"
    local STD="시스템 관리나 운용에 불필요한 그룹이 제거된 경우"
    local RES=""
    local DESC=""
    local DT=""

    # 사용 중인 GID 목록 (passwd 파일의 기본 GID)
    typeset USED_GIDS=$(cut -d: -f4 /etc/passwd 2>/dev/null | sort -u)

    # 사용되지 않는 그룹 확인 (시스템 그룹 GID < 100 제외)
    typeset UNUSED_GROUPS=""
    while IFS=: read -r name pass gid members; do
        if is_number "$gid" && [ "$gid" -ge 100 ] 2>/dev/null; then
            if [ -z "$members" ]; then
                typeset FOUND="false"
                for used_gid in $USED_GIDS; do
                    if [ "$gid" = "$used_gid" ]; then
                        FOUND="true"
                        break
                    fi
                done
                if [ "$FOUND" = "false" ]; then
                    UNUSED_GROUPS="${UNUSED_GROUPS}${name}(GID:$gid) "
                fi
            fi
        fi
    done < /etc/group

    if [ -z "$UNUSED_GROUPS" ]; then
        RES="Y"
        DESC="불필요한 그룹이 존재하지 않음"
        DT="사용되지 않는 그룹: 없음"
    else
        RES="M"
        DESC="사용되지 않는 그룹 수동 확인 필요"
        DT="확인 필요 그룹: $UNUSED_GROUPS"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check10() {
    local CODE="U-10"
    local CAT="계정관리"
    local NAME="동일한 UID 금지"
    local IMP="중"
    local STD="동일한 UID로 설정된 사용자 계정이 존재하지 않는 경우"
    local RES=""
    local DESC=""
    local DT=""

        # 중복 UID 확인
        typeset DUP_UIDS=$(awk -F: '{print $3}' /etc/passwd 2>/dev/null | sort | uniq -d)

        if [ -z "$DUP_UIDS" ]; then
            RES="Y"
            DESC="동일한 UID를 가진 계정이 없음"
            DT="중복 UID: 없음"
        else
            typeset DUP_ACCOUNTS=""
            for uid in $DUP_UIDS; do
                typeset accounts=$(awk -F: -v uid="$uid" '$3 == uid {print $1}' /etc/passwd 2>/dev/null | tr '\n' ',' | sed 's/,$//')
                DUP_ACCOUNTS="${DUP_ACCOUNTS}UID=$uid: $accounts
    "
            done
            RES="N"
            DESC="동일한 UID를 가진 계정이 존재함"
            DT="$DUP_ACCOUNTS"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check11() {
    local CODE="U-11"
    local CAT="계정관리"
    local NAME="사용자 shell 점검"
    local IMP="하"
    local STD="로그인이 필요하지 않은 계정에 /bin/false(/sbin/nologin) 쉘이 부여된 경우"
    local RES=""
    local DESC=""
    local DT=""

    # 로그인이 불필요한 계정 목록 (Solaris 포함)
    typeset NOLOGIN_ACCOUNTS="daemon bin sys adm listen nobody nobody4 noaccess diag operator games gopher"
    typeset VULNERABLE_ACCOUNTS=""

    for acc in $NOLOGIN_ACCOUNTS; do
        typeset shell=$(grep "^${acc}:" /etc/passwd 2>/dev/null | cut -d: -f7)
        if [ -n "$shell" ]; then
            case "$shell" in
                */nologin|*/false)
                    # 안전한 쉘
                    ;;
                *)
                    VULNERABLE_ACCOUNTS="${VULNERABLE_ACCOUNTS}${acc}($shell) "
                    ;;
            esac
        fi
    done

    if [ -z "$VULNERABLE_ACCOUNTS" ]; then
        RES="Y"
        DESC="로그인 불필요 계정에 적절한 쉘 설정됨"
        DT="취약 계정: 없음"
    else
        RES="N"
        DESC="로그인 불필요 계정에 쉘이 부여됨"
        DT="취약 계정: $VULNERABLE_ACCOUNTS"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check12() {
    local CODE="U-12"
    local CAT="계정관리"
    local NAME="세션 종료 시간 설정"
    local IMP="하"
    local STD="Session Timeout이 600초(10분) 이하로 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

    typeset TMOUT_VALUE=""
    typeset DETAILS=""

    # /etc/profile 확인 (sh, ksh, bash)
    if [ -f /etc/profile ]; then
        typeset found=$(grep -E "^[[:space:]]*(export[[:space:]]+)?TMOUT=" /etc/profile 2>/dev/null | head -1)
        if [ -n "$found" ]; then
            TMOUT_VALUE=$(echo "$found" | sed 's/.*TMOUT=//' | tr -d ' ')
            DETAILS="/etc/profile TMOUT=$TMOUT_VALUE"
        fi
    fi

    # /etc/csh.cshrc 또는 /etc/csh.login 확인 (csh용 autologout)
    if [ -z "$TMOUT_VALUE" ]; then
        for csh_file in /etc/csh.cshrc /etc/csh.login; do
            if [ -f "$csh_file" ]; then
                typeset autologout=$(grep "^set autologout" "$csh_file" 2>/dev/null | head -1)
                if [ -n "$autologout" ]; then
                    typeset auto_val=$(echo "$autologout" | sed 's/.*=//' | tr -d ' ')
                    DETAILS="$csh_file autologout=$auto_val (분)"
                    # 분 단위를 초 단위로 변환 (비교용)
                    if is_number "$auto_val"; then
                        TMOUT_VALUE=$((auto_val * 60))
                    fi
                    break
                fi
            fi
        done
    fi

    # 판단
    if [ -z "$TMOUT_VALUE" ]; then
        RES="N"
        DESC="세션 종료 시간이 설정되지 않음"
        DT="TMOUT: not set"
    elif is_number "$TMOUT_VALUE" && [ "$TMOUT_VALUE" -le 600 ] 2>/dev/null; then
        RES="Y"
        DESC="세션 종료 시간이 적절히 설정됨"
        DT="$DETAILS (기준: 600초 이하)"
    else
        RES="N"
        DESC="세션 종료 시간이 600초 초과"
        DT="$DETAILS (기준: 600초 이하)"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check13() {
    local CODE="U-13"
    local CAT="계정관리"
    local NAME="안전한 비밀번호 암호화 알고리즘 사용"
    local IMP="중"
    local STD="SHA-2 이상의 안전한 비밀번호 암호화 알고리즘을 사용하는 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset DETAILS=""
        typeset HAS_WEAK="false"

        # /etc/shadow에서 암호화 알고리즘 확인
        typeset ENCRYPT_TYPES=$(awk -F: '$2 ~ /^\$/ {print substr($2,1,3)}' /etc/shadow 2>/dev/null | sort | uniq)
        DETAILS="사용 중인 알고리즘: "

        for type in $ENCRYPT_TYPES; do
            case "$type" in
                '$1$')
                    DETAILS="${DETAILS}MD5(취약) "
                    HAS_WEAK="true"
                    ;;
                '$5$')
                    DETAILS="${DETAILS}SHA-256 "
                    ;;
                '$6$')
                    DETAILS="${DETAILS}SHA-512 "
                    ;;
                *)
                    DETAILS="${DETAILS}${type} "
                    ;;
            esac
        done

        # /etc/security/policy.conf CRYPT_DEFAULT 확인
        if [ -f "$POLICY_CONFIG" ]; then
            typeset CRYPT_DEFAULT=$(grep "^CRYPT_DEFAULT" "$POLICY_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
            DETAILS="$DETAILS
    CRYPT_DEFAULT: ${CRYPT_DEFAULT:-not set}"

            # CRYPT_DEFAULT가 1(MD5)이면 취약
            case "$CRYPT_DEFAULT" in
                1)
                    HAS_WEAK="true"
                    ;;
            esac
        fi

        if [ "$HAS_WEAK" = "true" ]; then
            RES="N"
            DESC="취약한 암호화 알고리즘(MD5) 사용 중"
        else
            RES="Y"
            DESC="안전한 암호화 알고리즘 사용 중"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check14() {
    local CODE="U-14"
    local CAT="파일및디렉토리관리"
    local NAME="root 홈, 패스 디렉터리 권한 및 패스 설정"
    local IMP="상"
    local STD="PATH 환경변수에 “.” 이 맨 앞이나 중간에 포함되지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

        # PATH에 . 또는 :: 포함 여부 확인
        typeset ROOT_PATH=$(su - root -c 'echo $PATH' 2>/dev/null)
        typeset HAS_DOT="false"

        # PATH에 현재 디렉토리(.)가 맨 앞이나 중간에 포함되어 있는지 확인
        case "$ROOT_PATH" in
            .*|*:.:*|*:.|::*)
                HAS_DOT="true"
                ;;
        esac

        # root 홈 디렉토리 권한 확인 (Solaris root 홈: / 또는 /root)
        typeset ROOT_HOME="/"
        typeset ROOT_HOME_DIR=$(grep "^root:" /etc/passwd 2>/dev/null | cut -d: -f6)
        if [ -n "$ROOT_HOME_DIR" ] && [ -d "$ROOT_HOME_DIR" ]; then
            ROOT_HOME="$ROOT_HOME_DIR"
        fi
        typeset ROOT_HOME_PERM=$(get_file_perm "$ROOT_HOME")

        if [ "$HAS_DOT" = "true" ]; then
            RES="N"
            DESC="PATH에 . 이 포함되어 있음"
            DT="PATH: $ROOT_PATH
    root 홈($ROOT_HOME) 권한: $ROOT_HOME_PERM"
        elif is_number "$ROOT_HOME_PERM" && [ "$ROOT_HOME_PERM" -gt 750 ] 2>/dev/null; then
            RES="N"
            DESC="root 홈 디렉토리 권한이 과도함"
            DT="root 홈($ROOT_HOME) 권한: $ROOT_HOME_PERM (기준: 750 이하)"
        else
            RES="Y"
            DESC="PATH 및 root 홈 디렉토리 설정 양호"
            DT="PATH: $ROOT_PATH
    root 홈($ROOT_HOME) 권한: $ROOT_HOME_PERM"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check15() {
    local CODE="U-15"
    local CAT="파일및디렉토리관리"
    local NAME="파일 및 디렉터리 소유자 설정"
    local IMP="상"
    local STD="소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않는 경우"
    local RES=""
    local DESC=""
    local DT=""

        # 소유자가 없는 파일 확인 (주요 디렉토리만, -xdev로 마운트 경계 제한)
        typeset NOOWNER=$(find /etc /var /tmp -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -10)

        if [ -z "$NOOWNER" ]; then
            RES="Y"
            DESC="소유자가 없는 파일이 존재하지 않음"
            DT="소유자 없는 파일: 없음"
        else
            typeset NOOWNER_CNT=$(find /etc /var /tmp -xdev \( -nouser -o -nogroup \) 2>/dev/null | wc -l | tr -d ' ')
            RES="N"
            DESC="소유자가 없는 파일이 존재함 (${NOOWNER_CNT}건)"
            DT="소유자 없는 파일 (상위 10건):
    $NOOWNER"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check16() {
    local CODE="U-16"
    local CAT="파일및디렉토리관리"
    local NAME="/etc/passwd 파일 소유자 및 권한 설정"
    local IMP="상"
    local STD="/etc/passwd 파일의 소유자가 root이고, 권한이 644 이하인 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset TARGET="/etc/passwd"

        if [ ! -f "$TARGET" ]; then
            RES="N/A"
            DESC="파일이 존재하지 않음"
            DT="파일: $TARGET (없음)"
        else
            typeset PERM=$(get_file_perm "$TARGET")
            typeset OWNER=$(get_file_owner "$TARGET")

            if [ "$OWNER" = "root" ] && is_number "$PERM" && [ "$PERM" -le 644 ] 2>/dev/null; then
                RES="Y"
                DESC="파일 권한이 적절히 설정됨"
            else
                RES="N"
                DESC="파일 권한이 부적절함"
            fi
            DT="파일: $TARGET
    소유자: $OWNER
    권한: $PERM"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check17() {
    local CODE="U-17"
    local CAT="파일및디렉토리관리"
    local NAME="시스템 시작 스크립트 권한 설정"
    local IMP="상"
    local STD="시스템 시작 스크립트 파일의 소유자가 root이고, 일반 사용자의 쓰기 권한이 제거된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset VULNERABLE=""
        # Solaris 시스템 시작 스크립트 디렉토리
        typeset TARGETS="/etc/rc.d /etc/init.d /etc/rc0.d /etc/rc1.d /etc/rc2.d /etc/rc3.d"
        typeset CHECKED_LIST=""

        for target in $TARGETS; do
            if [ -d "$target" ]; then
                typeset dir_perm=$(get_file_perm "$target")
                typeset dir_owner=$(get_file_owner "$target")
                CHECKED_LIST="${CHECKED_LIST}  - ${target} (${dir_owner}:${dir_perm})
    "
                # 디렉토리 내 스크립트 파일 검사
                for script in "$target"/*; do
                    if [ -f "$script" ]; then
                        typeset s_perm=$(get_file_perm "$script")
                        typeset s_owner=$(get_file_owner "$script")
                        # other 쓰기 권한(2) 여부 확인
                        typeset other_w=$((s_perm % 10))
                        if [ "$s_owner" != "root" ] || [ $((other_w & 2)) -ne 0 ] 2>/dev/null; then
                            VULNERABLE="${VULNERABLE}${script}(${s_owner}:${s_perm}) "
                        fi
                    fi
                done
            fi
        done

        if [ -z "$CHECKED_LIST" ]; then
            RES="N/A"
            DESC="시스템 시작 스크립트 디렉토리를 찾을 수 없음"
            DT="검사 대상 디렉토리: 없음"
        elif [ -z "$VULNERABLE" ]; then
            RES="Y"
            DESC="시스템 시작 스크립트 권한 양호"
            DT="[검사 대상]
    ${CHECKED_LIST}
    [취약 파일]
    없음"
        else
            RES="N"
            DESC="시스템 시작 스크립트 권한 부적절"
            DT="[검사 대상]
    ${CHECKED_LIST}
    [취약 파일]
    $VULNERABLE"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check18() {
    local CODE="U-18"
    local CAT="파일및디렉토리관리"
    local NAME="/etc/shadow 파일 소유자 및 권한 설정"
    local IMP="상"
    local STD="/etc/shadow 파일의 소유자가 root이고, 권한이 400 이하인 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset TARGET="/etc/shadow"

        if [ ! -f "$TARGET" ]; then
            RES="N/A"
            DESC="파일이 존재하지 않음"
            DT="파일: $TARGET (없음)"
        else
            typeset PERM=$(get_file_perm "$TARGET")
            typeset OWNER=$(get_file_owner "$TARGET")

            if [ "$OWNER" = "root" ] && [ "$PERM" -le 400 ] 2>/dev/null; then
                RES="Y"
                DESC="파일 권한이 적절히 설정됨"
            else
                RES="N"
                DESC="파일 권한이 부적절함"
            fi
            DT="파일: $TARGET
    소유자: $OWNER
    권한: $PERM (기준: 400 이하)"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check19() {
    local CODE="U-19"
    local CAT="파일및디렉토리관리"
    local NAME="/etc/hosts 파일 소유자 및 권한 설정"
    local IMP="상"
    local STD="/etc/hosts 파일의 소유자가 root이고, 권한이 644 이하인 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset TARGET="/etc/hosts"

        if [ ! -f "$TARGET" ]; then
            RES="N/A"
            DESC="파일이 존재하지 않음"
            DT="파일: $TARGET (없음)"
        else
            typeset PERM=$(get_file_perm "$TARGET")
            typeset OWNER=$(get_file_owner "$TARGET")

            if [ "$OWNER" = "root" ] && [ "$PERM" -le 644 ] 2>/dev/null; then
                RES="Y"
                DESC="파일 권한이 적절히 설정됨"
            else
                RES="N"
                DESC="파일 권한이 부적절함"
            fi
            DT="파일: $TARGET
    소유자: $OWNER
    권한: $PERM"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check20() {
    local CODE="U-20"
    local CAT="파일및디렉토리관리"
    local NAME="/etc/(x)inetd.conf 파일 소유자 및 권한 설정"
    local IMP="상"
    local STD="/etc/(x)inetd.conf 파일의 소유자가 root이고, 권한이 600 이하인 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset TARGETS="/etc/inetd.conf /etc/xinetd.conf"
        typeset FOUND="false"
        typeset VULNERABLE=""
        typeset DETAILS=""

        for target in $TARGETS; do
            if [ -f "$target" ]; then
                FOUND="true"
                typeset perm=$(get_file_perm "$target")
                typeset owner=$(get_file_owner "$target")
                DETAILS="${DETAILS}${target}: ${owner}:${perm}
    "
                if [ "$owner" != "root" ] || [ "$perm" -gt 600 ] 2>/dev/null; then
                    VULNERABLE="${VULNERABLE}${target} "
                fi
            fi
        done

        if [ "$FOUND" = "false" ]; then
            RES="N/A"
            DESC="inetd/xinetd 설정 파일이 존재하지 않음"
            DT="(x)inetd.conf: 미사용"
        elif [ -z "$VULNERABLE" ]; then
            RES="Y"
            DESC="파일 권한이 적절히 설정됨"
            DT="$DETAILS"
        else
            RES="N"
            DESC="파일 권한이 부적절함"
            DT="${DETAILS}취약 파일: $VULNERABLE"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check21() {
    local CODE="U-21"
    local CAT="파일및디렉토리관리"
    local NAME="/etc/(r)syslog.conf 파일 소유자 및 권한 설정"
    local IMP="상"
    local STD="/etc/(r)syslog.conf 파일의 소유자가 root(또는 bin, sys)이고, 권한이 640 이하인 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset TARGETS="/etc/syslog.conf /etc/rsyslog.conf"
        typeset FOUND="false"
        typeset VULNERABLE=""
        typeset DETAILS=""

        for target in $TARGETS; do
            if [ -f "$target" ]; then
                FOUND="true"
                typeset perm=$(get_file_perm "$target")
                typeset owner=$(get_file_owner "$target")
                DETAILS="${DETAILS}${target}: ${owner}:${perm}
    "
                if { [ "$owner" != "root" ] && [ "$owner" != "bin" ] && [ "$owner" != "sys" ]; } || [ "$perm" -gt 640 ] 2>/dev/null; then
                    VULNERABLE="${VULNERABLE}${target} "
                fi
            fi
        done

        if [ "$FOUND" = "false" ]; then
            RES="N/A"
            DESC="syslog 설정 파일이 존재하지 않음"
            DT="(r)syslog.conf: 없음"
        elif [ -z "$VULNERABLE" ]; then
            RES="Y"
            DESC="파일 권한이 적절히 설정됨"
            DT="$DETAILS"
        else
            RES="N"
            DESC="파일 권한이 부적절함"
            DT="${DETAILS}취약 파일: $VULNERABLE"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check22() {
    local CODE="U-22"
    local CAT="파일및디렉토리관리"
    local NAME="/etc/services 파일 소유자 및 권한 설정"
    local IMP="상"
    local STD="/etc/services 파일의 소유자가 root(또는 bin, sys)이고, 권한이 644 이하인 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset TARGET="/etc/services"

        if [ ! -f "$TARGET" ]; then
            RES="N/A"
            DESC="파일이 존재하지 않음"
            DT="파일: $TARGET (없음)"
        else
            typeset PERM=$(get_file_perm "$TARGET")
            typeset OWNER=$(get_file_owner "$TARGET")

            if { [ "$OWNER" = "root" ] || [ "$OWNER" = "bin" ] || [ "$OWNER" = "sys" ]; } && [ "$PERM" -le 644 ] 2>/dev/null; then
                RES="Y"
                DESC="파일 권한이 적절히 설정됨"
            else
                RES="N"
                DESC="파일 권한이 부적절함"
            fi
            DT="파일: $TARGET
    소유자: $OWNER
    권한: $PERM"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check23() {
    local CODE="U-23"
    local CAT="파일및디렉토리관리"
    local NAME="SUID, SGID, Sticky bit 설정 파일 점검"
    local IMP="상"
    local STD="주요 실행 파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

        # SUID/SGID 파일 검색 (주요 디렉토리만)
        typeset SUID_FILES=$(find /usr /bin /sbin -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -20)
        typeset COUNT=0
        if [ -n "$SUID_FILES" ]; then
            COUNT=$(printf "%s\n" "$SUID_FILES" | grep -c .)
        fi

        RES="M"
        DESC="SUID/SGID 파일 수동 확인 필요 (${COUNT}개 발견)"
        DT="SUID/SGID 파일 목록:
    $SUID_FILES
    ...(상위 20개만 표시)"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check24() {
    local CODE="U-24"
    local CAT="파일및디렉토리관리"
    local NAME="사용자, 시스템 환경변수 파일 소유자 및 권한 설정"
    local IMP="상"
    local STD="홈 디렉터리 환경변수 파일 소유자가 root 또는 해당 계정으로 지정되어 있고, 홈 디렉터리 환경변수 파일에 root 계정과 소유자만 쓰기 권한이 부여된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset TARGETS="/etc/profile /etc/.login /.profile /.cshrc /.login"
        typeset VULNERABLE=""
        typeset DETAILS=""

        for target in $TARGETS; do
            if [ -f "$target" ]; then
                typeset perm=$(get_file_perm "$target")
                typeset owner=$(get_file_owner "$target")
                DETAILS="${DETAILS}${target}: ${owner}:${perm}
    "
                if [ "$owner" != "root" ] || [ "$perm" -gt 644 ] 2>/dev/null; then
                    VULNERABLE="${VULNERABLE}${target} "
                fi
            fi
        done

        if [ -z "$VULNERABLE" ]; then
            RES="Y"
            DESC="환경변수 파일 권한 양호"
            DT="$DETAILS"
        else
            RES="N"
            DESC="환경변수 파일 권한 부적절"
            DT="${DETAILS}취약 파일: $VULNERABLE"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check25() {
    local CODE="U-25"
    local CAT="파일및디렉토리관리"
    local NAME="world writable 파일 점검"
    local IMP="상"
    local STD="world writable 파일이 존재하지 않거나, 존재 시 설정 이유를 인지하고 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

        # 검사 대상 디렉토리
        typeset SEARCH_DIRS="/etc /var"

        # world writable 파일 검색 (주요 디렉토리)
        typeset WW_FILES=$(find /etc /var -type f -perm -2 2>/dev/null | head -10)
        typeset WW_COUNT=0
        if [ -n "$WW_FILES" ]; then
            WW_COUNT=$(find /etc /var -type f -perm -2 2>/dev/null | wc -l)
        fi

        if [ -z "$WW_FILES" ]; then
            RES="Y"
            DESC="world writable 파일이 존재하지 않음"
            DT="[검사 대상 디렉토리]
      $SEARCH_DIRS

    [world writable 파일]
    없음"
        else
            RES="N"
            DESC="world writable 파일이 존재함 (${WW_COUNT}개)"
            DT="[검사 대상 디렉토리]
      $SEARCH_DIRS

    [world writable 파일] (최대 10개 표시)
    $WW_FILES"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check26() {
    local CODE="U-26"
    local CAT="파일및디렉토리관리"
    local NAME="/dev에 존재하지 않는 device 파일 점검"
    local IMP="상"
    local STD="/dev 디렉터리에 대한 파일 점검 후 존재하지 않는 device 파일을 제거한 경우"
    local RES=""
    local DESC=""
    local DT=""

        # 검사 제외 경로
        typeset EXCLUDE_PATHS="/dev, /proc, /devices"

        # /dev 외부의 device 파일 검색
        typeset DEV_FILES=$(find / \
            -path /dev -prune -o \
            -path /proc -prune -o \
            -path /devices -prune -o \
            \( -type b -o -type c \) -print 2>/dev/null | head -10)
        typeset DEV_COUNT=0
        if [ -n "$DEV_FILES" ]; then
            DEV_COUNT=$(find / \
                -path /dev -prune -o \
                -path /proc -prune -o \
                -path /devices -prune -o \
                \( -type b -o -type c \) -print 2>/dev/null | wc -l)
        fi

        if [ -z "$DEV_FILES" ]; then
            RES="Y"
            DESC="/dev 외부에 device 파일이 없음"
            DT="[검사 범위]
      전체 파일시스템 (/ 기준)

    [제외 경로]
      $EXCLUDE_PATHS

    [비정상 device 파일]
    없음"
        else
            RES="N"
            DESC="/dev 외부에 device 파일 존재 (${DEV_COUNT}개)"
            DT="[검사 범위]
      전체 파일시스템 (/ 기준)

    [제외 경로]
      $EXCLUDE_PATHS

    [비정상 device 파일] (최대 10개 표시)
    $DEV_FILES"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check27() {
    local CODE="U-27"
    local CAT="파일및디렉토리관리"
    local NAME="\$HOME/.rhosts, hosts.equiv 사용 금지"
    local IMP="상"
    local STD="rlogin, rsh, rexec 서비스를 사용하지 않거나, 사용 시 아래와 같은 설정이 적용된 경우 1. /etc/hosts.equiv 및 \$HOME/.rhosts 파일 소유자가 root 또는 해당 계정인 경우 2. /etc/hosts.equiv 및 \$HOME/.rhosts 파일 권한이 600 이하인 경우 3. /etc/hosts.equiv 및 \$HOME/.rhosts 파일 설정에 “+” 설정이 없는 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset VULNERABLE=""
        typeset DETAILS=""

        # r-command 서비스 실행 여부 확인
        typeset RCMD_RUNNING="false"
        if is_process_running "rlogind" || is_process_running "rshd" || is_process_running "rexecd"; then
            RCMD_RUNNING="true"
        fi

        # /etc/hosts.equiv 확인
        if [ -f /etc/hosts.equiv ]; then
            typeset perm=""
            typeset owner=""
            perm=$(get_file_perm /etc/hosts.equiv)
            owner=$(get_file_owner /etc/hosts.equiv)
            DETAILS="${DETAILS}/etc/hosts.equiv: ${owner}:${perm}
    "
            # + 설정 확인
            typeset PLUS_SET=""
            PLUS_SET=$(grep "^+" /etc/hosts.equiv 2>/dev/null)
            if [ -n "$PLUS_SET" ]; then
                DETAILS="${DETAILS}  + 설정 발견: 위험
    "
                VULNERABLE="${VULNERABLE}/etc/hosts.equiv(+설정) "
            fi
            if [ "$owner" != "root" ] || [ "$perm" -gt 600 ] 2>/dev/null; then
                VULNERABLE="${VULNERABLE}/etc/hosts.equiv(권한) "
            fi
        fi

        # 사용자 홈 디렉토리의 .rhosts 확인
        while IFS=: read -r user pass uid gid gecos home shell; do
            if [ -f "${home}/.rhosts" ] 2>/dev/null; then
                typeset perm=""
                typeset owner=""
                perm=$(get_file_perm "${home}/.rhosts")
                owner=$(get_file_owner "${home}/.rhosts")
                DETAILS="${DETAILS}${home}/.rhosts: ${owner}:${perm}
    "
                typeset PLUS_SET=""
                PLUS_SET=$(grep "^+" "${home}/.rhosts" 2>/dev/null)
                if [ -n "$PLUS_SET" ]; then
                    VULNERABLE="${VULNERABLE}${home}/.rhosts(+설정) "
                fi
                if [ "$owner" != "root" ] && [ "$owner" != "$user" ]; then
                    VULNERABLE="${VULNERABLE}${home}/.rhosts(소유자) "
                fi
                if [ "$perm" -gt 600 ] 2>/dev/null; then
                    VULNERABLE="${VULNERABLE}${home}/.rhosts(권한) "
                fi
            fi
        done < /etc/passwd

        if [ "$RCMD_RUNNING" = "false" ] && [ -z "$VULNERABLE" ]; then
            RES="Y"
            DESC="r-command 미사용 및 .rhosts/hosts.equiv 파일 양호"
            DT="r-command 서비스: 미실행
    ${DETAILS:-취약 파일: 없음}"
        elif [ -z "$VULNERABLE" ]; then
            RES="Y"
            DESC=".rhosts/hosts.equiv 파일 양호"
            DT="r-command 서비스: 실행중
    ${DETAILS:-취약 파일: 없음}"
        else
            RES="N"
            DESC=".rhosts/hosts.equiv 파일 취약"
            DT="r-command 서비스: $([ "$RCMD_RUNNING" = "true" ] && printf "실행중" || printf "미실행")
    $DETAILS
    [취약 항목]
    $VULNERABLE"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check28() {
    local CODE="U-28"
    local CAT="파일및디렉토리관리"
    local NAME="접속 IP 및 포트 제한"
    local IMP="상"
    local STD="접속을 허용할 특정 호스트에 대한 IP주소 및 포트 제한을 설정한 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset DETAILS=""
        typeset HAS_RESTRICTION="false"

        # hosts.allow / hosts.deny 확인
        if [ -f /etc/hosts.allow ]; then
            typeset ALLOW_CONTENT=$(grep -v "^#" /etc/hosts.allow 2>/dev/null | grep -v "^$" | head -5)
            if [ -n "$ALLOW_CONTENT" ]; then
                DETAILS="${DETAILS}hosts.allow:
    $ALLOW_CONTENT
    "
                HAS_RESTRICTION="true"
            fi
        fi

        if [ -f /etc/hosts.deny ]; then
            typeset DENY_CONTENT=$(grep -v "^#" /etc/hosts.deny 2>/dev/null | grep -v "^$" | head -5)
            if [ -n "$DENY_CONTENT" ]; then
                DETAILS="${DETAILS}hosts.deny:
    $DENY_CONTENT
    "
                HAS_RESTRICTION="true"
            fi
        fi

        # ipfilter 확인 (Solaris)
        if [ -f /etc/ipf/ipf.conf ]; then
            typeset IPF_RULES=$(grep -v "^#" /etc/ipf/ipf.conf 2>/dev/null | grep -v "^$" | head -5)
            if [ -n "$IPF_RULES" ]; then
                DETAILS="${DETAILS}ipfilter 설정:
    $IPF_RULES
    "
                HAS_RESTRICTION="true"
            fi
        fi

        if [ "$HAS_RESTRICTION" = "true" ]; then
            RES="Y"
            DESC="접속 IP/포트 제한이 설정됨"
        else
            RES="N"
            DESC="접속 IP/포트 제한이 미설정"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check29() {
    local CODE="U-29"
    local CAT="파일및디렉토리관리"
    local NAME="hosts.lpd 파일 소유자 및 권한 설정"
    local IMP="하"
    local STD="/etc/hosts.lpd 파일이 존재하지 않거나, 불가피하게 사용 시 /etc/hosts.lpd 파일의 소유자가 root이고, 권한이 600 이하인 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset TARGET="/etc/hosts.lpd"

        if [ ! -f "$TARGET" ]; then
            RES="N/A"
            DESC="파일이 존재하지 않음"
            DT="파일: $TARGET (없음)"
        else
            typeset PERM=$(get_file_perm "$TARGET")
            typeset OWNER=$(get_file_owner "$TARGET")

            if [ "$OWNER" = "root" ] && [ "$PERM" -le 600 ] 2>/dev/null; then
                RES="Y"
                DESC="파일 권한이 적절히 설정됨"
            else
                RES="N"
                DESC="파일 권한이 부적절함"
            fi
            DT="파일: $TARGET
    소유자: $OWNER
    권한: $PERM"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check30() {
    local CODE="U-30"
    local CAT="파일및디렉토리관리"
    local NAME="UMASK 설정 관리"
    local IMP="중"
    local STD="UMASK 값이 022 이상으로 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset UMASK_VALUE=""
        typeset DETAILS=""

        # /etc/profile 확인
        UMASK_VALUE=$(grep -i "^umask" /etc/profile 2>/dev/null | awk '{print $2}' | head -1)
        if [ -n "$UMASK_VALUE" ]; then
            DETAILS="/etc/profile UMASK=$UMASK_VALUE"
        fi

        # /etc/default/login 확인 (Solaris)
        if [ -z "$UMASK_VALUE" ] && [ -f /etc/default/login ]; then
            UMASK_VALUE=$(grep "^UMASK" /etc/default/login 2>/dev/null | cut -d'=' -f2)
            if [ -n "$UMASK_VALUE" ]; then
                DETAILS="/etc/default/login UMASK=$UMASK_VALUE"
            fi
        fi

        # 현재 umask
        typeset CURRENT_UMASK=$(umask)
        DETAILS="${DETAILS}
    현재 UMASK: $CURRENT_UMASK"

        # 판단: "022 이상" = group/other write bit가 마스킹 (group>=2 AND other>=2)
        typeset CHECK_VAL=""
        if [ -n "$UMASK_VALUE" ]; then
            CHECK_VAL="$UMASK_VALUE"
        else
            CHECK_VAL="$CURRENT_UMASK"
        fi

        # 앞의 0 제거 후 3자리 패딩
        typeset NORM=""
        NORM=$(echo "$CHECK_VAL" | sed 's/^0*//')
        [ -z "$NORM" ] && NORM="0"

        typeset IS_OK="false"
        if is_number "$NORM"; then
            typeset PADDED=""
            PADDED=$(printf "%03d" "$NORM")
            typeset G_DIGIT=""
            typeset O_DIGIT=""
            G_DIGIT=$(echo "$PADDED" | cut -c2)
            O_DIGIT=$(echo "$PADDED" | cut -c3)
            if [ "$G_DIGIT" -ge 2 ] 2>/dev/null && [ "$O_DIGIT" -ge 2 ] 2>/dev/null; then
                IS_OK="true"
            fi
        fi

        if [ "$IS_OK" = "true" ]; then
            RES="Y"
            DESC="UMASK가 적절히 설정됨 ($CHECK_VAL)"
        else
            RES="N"
            DESC="UMASK 설정이 부적절함 ($CHECK_VAL)"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check31() {
    local CODE="U-31"
    local CAT="파일및디렉토리관리"
    local NAME="홈디렉토리 소유자 및 권한 설정"
    local IMP="중"
    local STD="홈 디렉토리 소유자가 해당 계정이고, 타 사용자 쓰기 권한이 제거된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset VULNERABLE=""
        typeset DETAILS=""

        while IFS=: read -r user pass uid gid gecos home shell; do
            if [ "$uid" -ge 100 ] 2>/dev/null && [ -d "$home" ]; then
                typeset perm=$(get_file_perm "$home")
                typeset owner=$(get_file_owner "$home")
                # other 쓰기 권한(2) 여부 확인
                typeset other_perm=$((perm % 10))
                if [ "$owner" != "$user" ] || [ $((other_perm & 2)) -ne 0 ] 2>/dev/null; then
                    VULNERABLE="${VULNERABLE}${home}(${owner}:${perm}) "
                fi
                DETAILS="${DETAILS}${user}: ${home}(${owner}:${perm})
    "
            fi
        done < /etc/passwd

        if [ -z "$VULNERABLE" ]; then
            RES="Y"
            DESC="홈 디렉토리 권한 양호"
        else
            RES="N"
            DESC="홈 디렉토리 권한 부적절"
        fi
        DT="${DETAILS}취약: ${VULNERABLE:-없음}"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check32() {
    local CODE="U-32"
    local CAT="파일및디렉토리관리"
    local NAME="홈 디렉토리로 지정한 디렉토리의 존재 관리"
    local IMP="중"
    local STD="홈 디렉토리가 존재하지 않는 계정이 발견되지 않는 경우"
    local RES=""
    local DESC=""
    local DT=""

    typeset MISSING=""
    typeset DETAILS=""

    while IFS=: read -r user pass uid gid gecos home shell; do
        if [ "$uid" -ge 100 ] 2>/dev/null; then
            if [ ! -d "$home" ]; then
                MISSING="${MISSING}${user}:${home} "
            fi
        fi
    done < /etc/passwd

    if [ -z "$MISSING" ]; then
        RES="Y"
        DESC="모든 홈 디렉토리가 존재함"
        DT="누락된 홈 디렉토리: 없음"
    else
        RES="N"
        DESC="존재하지 않는 홈 디렉토리 있음"
        DT="누락된 홈 디렉토리: $MISSING"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check33() {
    local CODE="U-33"
    local CAT="파일및디렉토리관리"
    local NAME="숨겨진 파일 및 디렉토리 검색 및 제거"
    local IMP="하"
    local STD="불필요하거나 의심스러운 숨겨진 파일 및 디렉토리를 제거한 경우"
    local RES=""
    local DESC=""
    local DT=""

        # 홈 디렉토리에서 숨김 파일 검색
        typeset HIDDEN_FILES=$(find /home /export/home / -maxdepth 3 -name ".*" -type f 2>/dev/null | head -20)
        typeset COUNT=0
        if [ -n "$HIDDEN_FILES" ]; then
            COUNT=$(printf "%s\n" "$HIDDEN_FILES" | grep -c .)
        fi

        RES="M"
        DESC="숨김 파일 수동 확인 필요 (${COUNT}개 발견)"
        DT="숨김 파일 목록:
    $HIDDEN_FILES
    ...(상위 20개만 표시)"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check34() {
    local CODE="U-34"
    local CAT="서비스관리"
    local NAME="Finger 서비스 비활성화"
    local IMP="상"
    local STD="Finger 서비스가 비활성화된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset RUNNING="false"
        typeset DETAILS=""

        # inetadm (Solaris 10+) 확인
        if [ -x /usr/sbin/inetadm ]; then
            typeset FINGER_SVC=$(inetadm 2>/dev/null | grep -i finger)
            if [ -n "$FINGER_SVC" ]; then
                case "$FINGER_SVC" in
                    *enabled*)
                        RUNNING="true"
                        DETAILS="inetadm finger: enabled
    $FINGER_SVC"
                        ;;
                    *)
                        DETAILS="inetadm finger: disabled
    $FINGER_SVC"
                        ;;
                esac
            fi
        fi

        # /etc/inetd.conf 확인 (레거시)
        if [ -f /etc/inetd.conf ]; then
            typeset FINGER_INETD=$(grep "^finger" /etc/inetd.conf 2>/dev/null)
            if [ -n "$FINGER_INETD" ]; then
                RUNNING="true"
                DETAILS="${DETAILS}
    inetd.conf finger: 활성화
    $FINGER_INETD"
            fi
        fi

        # 프로세스 확인
        if is_process_running "fingerd"; then
            RUNNING="true"
            DETAILS="${DETAILS}
    fingerd 프로세스: 실행 중"
        fi

        # 포트 79 확인
        if netstat -an 2>/dev/null | grep -q "\.79 .*LISTEN"; then
            RUNNING="true"
            DETAILS="${DETAILS}
    포트 79: LISTEN 상태"
        fi

        if [ "$RUNNING" = "true" ]; then
            RES="N"
            DESC="Finger 서비스가 활성화되어 있음"
        else
            RES="Y"
            DESC="Finger 서비스가 비활성화됨"
            if [ -z "$DETAILS" ]; then
                DETAILS="fingerd: 미실행"
            fi
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check35() {
    local CODE="U-35"
    local CAT="서비스관리"
    local NAME="공유 서비스에 대한 익명 접근 제한 설정"
    local IMP="상"
    local STD="공유 서비스에 대해 익명 접근을 제한한 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset VULNERABLE="false"
        typeset DETAILS=""
        typeset SVC_FOUND="false"

        # FTP 익명 계정 확인
        if grep -q "^ftp:" /etc/passwd 2>/dev/null; then
            VULNERABLE="true"
            SVC_FOUND="true"
            DETAILS="FTP ftp 계정: 존재
    "
        fi
        if grep -q "^anonymous:" /etc/passwd 2>/dev/null; then
            VULNERABLE="true"
            SVC_FOUND="true"
            DETAILS="${DETAILS}FTP anonymous 계정: 존재
    "
        fi

        # vsftpd 확인
        typeset VSFTPD_CONF=""
        for f in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf /usr/local/etc/vsftpd.conf; do
            if [ -f "$f" ]; then
                VSFTPD_CONF="$f"
                break
            fi
        done
        if [ -n "$VSFTPD_CONF" ]; then
            SVC_FOUND="true"
            typeset ANON_ENABLE=$(grep -i "^anonymous_enable" "$VSFTPD_CONF" 2>/dev/null)
            if [ -n "$ANON_ENABLE" ]; then
                typeset ANON_VAL=$(printf "%s" "$ANON_ENABLE" | tr 'A-Z' 'a-z')
                case "$ANON_VAL" in
                    *yes*)
                        VULNERABLE="true"
                        DETAILS="${DETAILS}vsftpd anonymous_enable=YES (취약)
    "
                        ;;
                    *)
                        DETAILS="${DETAILS}vsftpd anonymous_enable=NO (양호)
    "
                        ;;
                esac
            fi
        fi

        # proftpd 확인
        typeset PROFTPD_CONF=""
        for f in /etc/proftpd/proftpd.conf /etc/proftpd.conf /usr/local/etc/proftpd.conf; do
            if [ -f "$f" ]; then
                PROFTPD_CONF="$f"
                break
            fi
        done
        if [ -n "$PROFTPD_CONF" ]; then
            SVC_FOUND="true"
            typeset ANON_BLOCK=$(grep -c "<Anonymous" "$PROFTPD_CONF" 2>/dev/null)
            if [ "$ANON_BLOCK" -gt 0 ] 2>/dev/null; then
                VULNERABLE="true"
                DETAILS="${DETAILS}proftpd Anonymous 블록: 존재 (취약)
    "
            else
                DETAILS="${DETAILS}proftpd Anonymous 블록: 없음 (양호)
    "
            fi
        fi

        # NFS 익명 접근 확인 (/etc/dfs/dfstab)
        if [ -f /etc/dfs/dfstab ]; then
            typeset DFSTAB=$(grep -v "^#" /etc/dfs/dfstab 2>/dev/null | grep -v "^$")
            if [ -n "$DFSTAB" ]; then
                SVC_FOUND="true"
                DETAILS="${DETAILS}NFS dfstab:
    $DFSTAB
    "
                if printf "%s" "$DFSTAB" | grep -q "anon="; then
                    typeset ANON_NFS=$(printf "%s" "$DFSTAB" | grep -o "anon=[0-9-]*" | head -1)
                    if [ "$ANON_NFS" != "anon=-1" ]; then
                        VULNERABLE="true"
                        DETAILS="${DETAILS}NFS anon 값이 -1이 아님 (취약)
    "
                    fi
                fi
            fi
        fi

        # Samba 확인
        typeset SMB_CONF=""
        for f in /etc/samba/smb.conf /etc/smb.conf /usr/local/samba/lib/smb.conf; do
            if [ -f "$f" ]; then
                SMB_CONF="$f"
                break
            fi
        done
        if [ -n "$SMB_CONF" ]; then
            SVC_FOUND="true"
            typeset GUEST=$(grep -i "guest ok" "$SMB_CONF" 2>/dev/null | grep -i "yes")
            if [ -n "$GUEST" ]; then
                VULNERABLE="true"
                DETAILS="${DETAILS}Samba guest ok = yes (취약)
    "
            else
                DETAILS="${DETAILS}Samba guest ok: 미설정 또는 no (양호)
    "
            fi
        fi

        if [ "$SVC_FOUND" = "false" ]; then
            RES="N/A"
            DESC="공유 서비스가 구성되지 않음"
            DETAILS="FTP/NFS/Samba: 미구성"
        elif [ "$VULNERABLE" = "true" ]; then
            RES="N"
            DESC="익명 접근이 허용되어 있음"
        else
            RES="Y"
            DESC="익명 접근이 제한됨"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check36() {
    local CODE="U-36"
    local CAT="서비스관리"
    local NAME="r 계열 서비스 비활성화"
    local IMP="상"
    local STD="불필요한 r 계열 서비스가 비활성화된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset RUNNING=""
        typeset DETAILS=""

        # inetadm (Solaris 10+) 확인
        if [ -x /usr/sbin/inetadm ]; then
            typeset R_SVCS=$(inetadm 2>/dev/null | grep -E "shell|rlogin|rexec")
            if [ -n "$R_SVCS" ]; then
                DETAILS="inetadm r 계열 서비스:
    $R_SVCS"
                case "$R_SVCS" in
                    *enabled*)
                        RUNNING="smf_enabled"
                        ;;
                esac
            fi
        fi

        # /etc/inetd.conf 확인 (레거시)
        if [ -f /etc/inetd.conf ]; then
            typeset R_INETD=$(grep -E "^(shell|login|exec)" /etc/inetd.conf 2>/dev/null)
            if [ -n "$R_INETD" ]; then
                RUNNING="${RUNNING}inetd_enabled "
                DETAILS="${DETAILS}
    inetd.conf r 계열:
    $R_INETD"
            fi
        fi

        # 프로세스 확인
        for svc in rlogind rshd rexecd in.rlogind in.rshd in.rexecd; do
            if is_process_running "$svc"; then
                RUNNING="${RUNNING}${svc} "
            fi
        done

        # 포트 확인 (512:exec, 513:login, 514:shell)
        if netstat -an 2>/dev/null | grep -E "\.51[234] .*LISTEN" | grep -v "^$" >/dev/null 2>&1; then
            typeset R_PORTS=$(netstat -an 2>/dev/null | grep -E "\.51[234] .*LISTEN")
            DETAILS="${DETAILS}
    r 계열 포트:
    $R_PORTS"
            if [ -z "$RUNNING" ]; then
                RUNNING="port_active"
            fi
        fi

        if [ -z "$RUNNING" ]; then
            RES="Y"
            DESC="r 계열 서비스가 비활성화됨"
            DT="r 계열 서비스: 미실행"
        else
            RES="N"
            DESC="r 계열 서비스가 실행 중"
            DT="$DETAILS"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check37() {
    local CODE="U-37"
    local CAT="서비스관리"
    local NAME="crontab 설정파일 권한 설정 미흡"
    local IMP="상"
    local STD="crontab 및 at 명령어에 일반 사용자 실행 권한이 제거되어 있으며, cron 및 at 관련 파일 권한이 640 이하인 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset VULNERABLE=""
        typeset DETAILS=""

        # crontab/at 명령어 파일 권한 확인 (750 이하)
        for cmd_file in /usr/bin/crontab /usr/bin/at; do
            if [ -f "$cmd_file" ]; then
                typeset perm=$(get_file_perm "$cmd_file")
                typeset owner=$(get_file_owner "$cmd_file")
                DETAILS="${DETAILS}${cmd_file}: ${owner}:${perm}
    "
                if [ "$owner" != "root" ]; then
                    VULNERABLE="${VULNERABLE}${cmd_file}(소유자:${owner}) "
                fi
                # other 실행 권한 확인
                typeset other_perm=$((perm % 10))
                if [ "$other_perm" -gt 0 ]; then
                    VULNERABLE="${VULNERABLE}${cmd_file}(other:${other_perm}) "
                fi
            fi
        done

        # cron 작업 목록 파일 (Solaris: /var/spool/cron/crontabs)
        if [ -d /var/spool/cron/crontabs ]; then
            typeset perm=$(get_file_perm "/var/spool/cron/crontabs")
            typeset owner=$(get_file_owner "/var/spool/cron/crontabs")
            DETAILS="${DETAILS}/var/spool/cron/crontabs: ${owner}:${perm}
    "
            if [ "$owner" != "root" ]; then
                VULNERABLE="${VULNERABLE}/var/spool/cron/crontabs(소유자:${owner}) "
            fi
        fi

        # cron 관련 파일 (Solaris: /etc/cron.d/)
        for cron_file in /etc/cron.d/cron.allow /etc/cron.d/cron.deny; do
            if [ -f "$cron_file" ]; then
                typeset perm=$(get_file_perm "$cron_file")
                typeset owner=$(get_file_owner "$cron_file")
                DETAILS="${DETAILS}${cron_file}: ${owner}:${perm}
    "
                if [ "$owner" != "root" ]; then
                    VULNERABLE="${VULNERABLE}${cron_file}(소유자:${owner}) "
                fi
                if [ "$perm" -gt 640 ] 2>/dev/null; then
                    VULNERABLE="${VULNERABLE}${cron_file}(권한:${perm}) "
                fi
            fi
        done

        # at 작업 목록 파일 (Solaris: /var/spool/cron/atjobs)
        if [ -d /var/spool/cron/atjobs ]; then
            typeset perm=$(get_file_perm "/var/spool/cron/atjobs")
            typeset owner=$(get_file_owner "/var/spool/cron/atjobs")
            DETAILS="${DETAILS}/var/spool/cron/atjobs: ${owner}:${perm}
    "
            if [ "$owner" != "root" ]; then
                VULNERABLE="${VULNERABLE}/var/spool/cron/atjobs(소유자:${owner}) "
            fi
        fi

        if [ -z "$VULNERABLE" ]; then
            RES="Y"
            DESC="crontab 설정 파일 권한 양호"
        else
            RES="N"
            DESC="crontab 설정 파일 권한 부적절"
        fi

        DT="${DETAILS}취약: ${VULNERABLE:-없음}"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check38() {
    local CODE="U-38"
    local CAT="서비스관리"
    local NAME="DoS 공격에 취약한 서비스 비활성화"
    local IMP="상"
    local STD="DoS 공격에 취약한 서비스가 비활성화된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset VULNERABLE_SVCS="echo discard daytime chargen"
        typeset RUNNING=""
        typeset DETAILS=""

        # inetadm (Solaris 10+) 확인
        if command -v inetadm >/dev/null 2>&1; then
            for svc in $VULNERABLE_SVCS; do
                typeset SVC_STATUS=$(inetadm 2>/dev/null | grep -i "$svc")
                if [ -n "$SVC_STATUS" ]; then
                    case "$SVC_STATUS" in
                        *enabled*)
                            RUNNING="${RUNNING}${svc} "
                            DETAILS="${DETAILS}inetadm ${svc}: enabled
    "
                            ;;
                        *)
                            DETAILS="${DETAILS}inetadm ${svc}: disabled
    "
                            ;;
                    esac
                fi
            done
        fi

        # /etc/inetd.conf 확인 (레거시)
        if [ -f /etc/inetd.conf ]; then
            for svc in $VULNERABLE_SVCS; do
                if grep -q "^$svc" /etc/inetd.conf 2>/dev/null; then
                    RUNNING="${RUNNING}${svc}(inetd) "
                    DETAILS="${DETAILS}inetd.conf ${svc}: 활성화
    "
                fi
            done
        fi

        if [ -z "$RUNNING" ]; then
            RES="Y"
            DESC="DoS 취약 서비스가 비활성화됨"
            if [ -z "$DETAILS" ]; then
                DETAILS="echo, discard, daytime, chargen: 비활성"
            fi
        else
            RES="N"
            DESC="DoS 취약 서비스가 활성화됨"
            DETAILS="활성화된 서비스: $RUNNING"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check39() {
    local CODE="U-39"
    local CAT="서비스관리"
    local NAME="불필요한 NFS 서비스 비활성화"
    local IMP="상"
    local STD="불필요한 NFS 서비스 관련 데몬이 비활성화된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset RUNNING="false"
        typeset DETAILS=""

        # SMF (Solaris 10+) NFS 서비스 확인
        if [ -x /usr/bin/svcs ]; then
            typeset NFS_STATUS=$(svcs -H svc:/network/nfs/server 2>/dev/null)
            if [ -n "$NFS_STATUS" ]; then
                case "$NFS_STATUS" in
                    *online*)
                        RUNNING="true"
                        DETAILS="NFS server (SMF): online
    $NFS_STATUS"
                        ;;
                    *)
                        DETAILS="NFS server (SMF): $(printf "%s" "$NFS_STATUS" | awk '{print $1}')"
                        ;;
                esac
            fi
        fi

        # inetadm NFS 관련 서비스 확인
        if command -v inetadm >/dev/null 2>&1; then
            typeset NFS_INET=$(inetadm 2>/dev/null | grep -E "nfs|statd|lockd")
            if [ -n "$NFS_INET" ]; then
                case "$NFS_INET" in
                    *enabled*)
                        RUNNING="true"
                        ;;
                esac
                DETAILS="${DETAILS}
    inetadm NFS 관련:
    $NFS_INET"
            fi
        fi

        # nfsd/mountd 프로세스 확인
        if is_process_running "nfsd"; then
            RUNNING="true"
            DETAILS="${DETAILS}
    nfsd 프로세스: 실행 중"
        fi
        if is_process_running "mountd"; then
            RUNNING="true"
            DETAILS="${DETAILS}
    mountd 프로세스: 실행 중"
        fi

        # 포트 2049 확인
        if netstat -an 2>/dev/null | grep -q "\.2049 .*LISTEN"; then
            RUNNING="true"
            DETAILS="${DETAILS}
    포트 2049: LISTEN 상태"
        fi

        if [ "$RUNNING" = "true" ]; then
            RES="M"
            DESC="NFS 서비스 사용 여부 수동 확인 필요"
        else
            RES="Y"
            DESC="NFS 서비스가 비활성화됨"
            if [ -z "$DETAILS" ]; then
                DETAILS="NFS: 미실행"
            fi
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check40() {
    local CODE="U-40"
    local CAT="서비스관리"
    local NAME="NFS 접근 통제"
    local IMP="상"
    local STD="접근 통제가 설정되어 있으며 NFS 설정 파일 접근 권한이 644 이하인 경우"
    local RES=""
    local DESC=""
    local DT=""

        # Solaris NFS 설정 파일
        typeset DFSTAB="/etc/dfs/dfstab"
        typeset SHARETAB="/etc/dfs/sharetab"

        if [ ! -f "$DFSTAB" ]; then
            RES="N/A"
            DESC="NFS dfstab 파일이 없음"
            DT="/etc/dfs/dfstab: 없음"
        else
            typeset DETAILS=""
            typeset HAS_ISSUE="false"

            # 파일 소유자 및 권한 확인
            typeset DF_OWNER=$(get_file_owner "$DFSTAB")
            typeset DF_PERM=$(get_file_perm "$DFSTAB")
            DETAILS="$DFSTAB: ${DF_OWNER}:${DF_PERM}"

            if [ "$DF_OWNER" != "root" ]; then
                HAS_ISSUE="true"
                DETAILS="${DETAILS} (소유자 부적절)"
            fi
            if [ "$DF_PERM" -gt 644 ] 2>/dev/null; then
                HAS_ISSUE="true"
                DETAILS="${DETAILS} (권한 초과)"
            fi

            # sharetab 파일 확인
            if [ -f "$SHARETAB" ]; then
                typeset ST_OWNER=$(get_file_owner "$SHARETAB")
                typeset ST_PERM=$(get_file_perm "$SHARETAB")
                DETAILS="${DETAILS}
    $SHARETAB: ${ST_OWNER}:${ST_PERM}"
            fi

            # 공유 설정 확인
            typeset SHARES=$(grep -v "^#" "$DFSTAB" 2>/dev/null | grep -v "^$")
            if [ -z "$SHARES" ]; then
                RES="Y"
                DESC="NFS 공유 설정이 없음"
                DT="${DETAILS}
    공유 설정: 없음"
            else
                DETAILS="${DETAILS}
    공유 설정:
    $SHARES"

                # 접근 통제 미설정 확인 (rw/ro에 호스트 지정 없이 공유)
                typeset UNRESTRICTED=""
                typeset LINE=""
                printf "%s\n" "$SHARES" | while read LINE; do
                    case "$LINE" in
                        *rw=*|*ro=*)
                            # 호스트가 지정되어 있으면 양호
                            ;;
                        *share*)
                            # rw/ro에 호스트 미지정
                            UNRESTRICTED="true"
                            ;;
                    esac
                done

                if printf "%s" "$SHARES" | grep -v "rw=" | grep -v "ro=" | grep -q "share"; then
                    HAS_ISSUE="true"
                fi

                if [ "$HAS_ISSUE" = "true" ]; then
                    RES="N"
                    DESC="NFS 접근 통제 미흡"
                else
                    RES="M"
                    DESC="NFS 접근 통제 수동 확인 필요"
                fi
                DT="$DETAILS"
            fi
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check41() {
    local CODE="U-41"
    local CAT="서비스관리"
    local NAME="불필요한 automountd 제거"
    local IMP="상"
    local STD="automountd 서비스가 비활성화된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset RUNNING="false"
        typeset DETAILS=""

        # SMF (Solaris 10+) autofs 서비스 확인
        if command -v svcs >/dev/null 2>&1; then
            typeset AUTOFS_STATUS=$(svcs -H svc:/system/filesystem/autofs 2>/dev/null)
            if [ -n "$AUTOFS_STATUS" ]; then
                case "$AUTOFS_STATUS" in
                    *online*)
                        RUNNING="true"
                        DETAILS="autofs (SMF): online
    $AUTOFS_STATUS"
                        ;;
                    *)
                        DETAILS="autofs (SMF): $(printf "%s" "$AUTOFS_STATUS" | awk '{print $1}')"
                        ;;
                esac
            fi
        fi

        # automountd 프로세스 확인
        if is_process_running "automountd"; then
            RUNNING="true"
            DETAILS="${DETAILS}
    automountd 프로세스: 실행 중"
        fi

        if [ "$RUNNING" = "true" ]; then
            RES="N"
            DESC="automountd가 실행 중"
        else
            RES="Y"
            DESC="automountd가 비활성화됨"
            if [ -z "$DETAILS" ]; then
                DETAILS="automount: 미실행"
            fi
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check42() {
    local CODE="U-42"
    local CAT="서비스관리"
    local NAME="불필요한 RPC 서비스 비활성화"
    local IMP="상"
    local STD="불필요한 RPC 서비스가 비활성화된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset RPC_PATTERNS="ttdbserver rex rstat ruser spray wall rquota"
        typeset RPC_PROCS="rpc.cmsd rpc.ttdbserverd sadmind rusersd walld sprayd rstatd rpc.nisd rexd rpc.pcnfsd rpc.statd rpc.ypupdated rpc.rquotad kcms_server cachefsd"
        typeset RUNNING=""
        typeset DETAILS=""

        # inetadm (Solaris 10+) 확인
        if [ -x /usr/sbin/inetadm ]; then
            typeset RPC_INETADM=$(inetadm 2>/dev/null | grep -i "rpc" | grep "enabled")
            if [ -n "$RPC_INETADM" ]; then
                # 불필요한 RPC 서비스만 필터링
                for pattern in $RPC_PATTERNS; do
                    typeset MATCH=$(printf "%s" "$RPC_INETADM" | grep -i "$pattern")
                    if [ -n "$MATCH" ]; then
                        RUNNING="${RUNNING}${pattern} "
                    fi
                done
                DETAILS="inetadm RPC 서비스 (enabled):
    $RPC_INETADM"
            fi
        fi

        # SMF (Solaris 10+) 확인
        if command -v svcs >/dev/null 2>&1; then
            for pattern in $RPC_PATTERNS; do
                typeset SVC_STATE=$(svcs -H 2>/dev/null | grep -i "$pattern" | grep "online")
                if [ -n "$SVC_STATE" ]; then
                    RUNNING="${RUNNING}${pattern}(smf) "
                fi
            done
        fi

        # 프로세스 확인
        for svc in $RPC_PROCS; do
            if is_process_running "$svc"; then
                RUNNING="${RUNNING}${svc} "
            fi
        done

        # rpcbind 상태 확인
        typeset RPCBIND_STATUS=""
        if is_process_running "rpcbind"; then
            RPCBIND_STATUS="rpcbind: 실행 중"
        else
            RPCBIND_STATUS="rpcbind: 미실행"
        fi

        if [ -z "$RUNNING" ]; then
            RES="Y"
            DESC="불필요한 RPC 서비스가 비활성화됨"
            DT="$RPCBIND_STATUS
    취약 RPC 서비스: 미실행"
        else
            RES="N"
            DESC="불필요한 RPC 서비스가 실행 중"
            DT="$RPCBIND_STATUS
    실행 중: $RUNNING
    $DETAILS"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check43() {
    local CODE="U-43"
    local CAT="서비스관리"
    local NAME="NIS, NIS+ 점검"
    local IMP="상"
    local STD="NIS 서비스가 비활성화되어 있거나, 불가피하게 사용 시 NIS+ 서비스를 사용하는 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset RUNNING="false"
        typeset DETAILS=""

        # SMF (Solaris 10+) NIS 서비스 확인
        if command -v svcs >/dev/null 2>&1; then
            typeset NIS_SVCS=$(svcs -a 2>/dev/null | grep -i nis)
            if [ -n "$NIS_SVCS" ]; then
                DETAILS="SMF NIS 서비스:
    $NIS_SVCS"
                case "$NIS_SVCS" in
                    *online*)
                        RUNNING="true"
                        ;;
                esac
            fi
        fi

        # NIS/NIS+ 프로세스 확인
        for svc in ypserv ypbind yppasswdd ypxfrd rpc.nisd rpc.ypupdated; do
            if is_process_running "$svc"; then
                RUNNING="true"
                DETAILS="${DETAILS}
    ${svc}: 실행 중"
            fi
        done

        if [ "$RUNNING" = "true" ]; then
            RES="N"
            DESC="NIS/NIS+ 서비스가 실행 중"
        else
            RES="Y"
            DESC="NIS/NIS+ 서비스가 비활성화됨"
            if [ -z "$DETAILS" ]; then
                DETAILS="NIS 서비스: 미실행"
            fi
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check44() {
    local CODE="U-44"
    local CAT="서비스관리"
    local NAME="tftp, talk 서비스 비활성화"
    local IMP="상"
    local STD="tftp, talk, ntalk 서비스가 비활성화된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset RUNNING=""
        typeset DETAILS=""

        # inetadm (Solaris 10+) 확인
        if [ -x /usr/sbin/inetadm ]; then
            typeset TFTP_SVC=$(inetadm 2>/dev/null | grep -i tftp)
            typeset TALK_SVC=$(inetadm 2>/dev/null | grep -i talk)

            if [ -n "$TFTP_SVC" ]; then
                case "$TFTP_SVC" in
                    *enabled*)
                        RUNNING="${RUNNING}tftp "
                        DETAILS="${DETAILS}inetadm tftp: enabled
    "
                        ;;
                    *)
                        DETAILS="${DETAILS}inetadm tftp: disabled
    "
                        ;;
                esac
            fi

            if [ -n "$TALK_SVC" ]; then
                case "$TALK_SVC" in
                    *enabled*)
                        RUNNING="${RUNNING}talk "
                        DETAILS="${DETAILS}inetadm talk: enabled
    "
                        ;;
                    *)
                        DETAILS="${DETAILS}inetadm talk: disabled
    "
                        ;;
                esac
            fi
        fi

        # /etc/inetd.conf 확인 (레거시)
        if [ -f /etc/inetd.conf ]; then
            if grep -q "^tftp" /etc/inetd.conf 2>/dev/null; then
                RUNNING="${RUNNING}tftp(inetd) "
                DETAILS="${DETAILS}inetd.conf tftp: 활성화
    "
            fi
            if grep -q "^talk\|^ntalk" /etc/inetd.conf 2>/dev/null; then
                RUNNING="${RUNNING}talk(inetd) "
                DETAILS="${DETAILS}inetd.conf talk/ntalk: 활성화
    "
            fi
        fi

        # 프로세스 확인
        if is_process_running "in.tftpd" || is_process_running "tftpd"; then
            RUNNING="${RUNNING}tftpd "
        fi
        if is_process_running "in.talkd" || is_process_running "talkd"; then
            RUNNING="${RUNNING}talkd "
        fi

        # 포트 확인 (tftp:69, talk:517, ntalk:518)
        if netstat -an 2>/dev/null | grep -E "\.(69|517|518) " | grep -v "^$" >/dev/null 2>&1; then
            typeset PORT_INFO=$(netstat -an 2>/dev/null | grep -E "\.(69|517|518) ")
            DETAILS="${DETAILS}관련 포트:
    $PORT_INFO"
        fi

        if [ -z "$RUNNING" ]; then
            RES="Y"
            DESC="tftp, talk 서비스가 비활성화됨"
            if [ -z "$DETAILS" ]; then
                DETAILS="tftp, talk, ntalk: 미실행"
            fi
        else
            RES="N"
            DESC="tftp 또는 talk 서비스가 실행 중"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check45() {
    local CODE="U-45"
    local CAT="서비스관리"
    local NAME="메일 서비스 버전 점검"
    local IMP="상"
    local STD="메일 서비스 버전이 최신 버전인 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset DETAILS=""
        typeset MAIL_FOUND="false"

        # Sendmail 확인
        typeset SENDMAIL_PATH=""
        if [ -x /usr/sbin/sendmail ]; then
            SENDMAIL_PATH="/usr/sbin/sendmail"
        elif [ -x /usr/lib/sendmail ]; then
            SENDMAIL_PATH="/usr/lib/sendmail"
        fi

        if [ -n "$SENDMAIL_PATH" ]; then
            MAIL_FOUND="true"
            typeset SENDMAIL_VER=$($SENDMAIL_PATH -d0.1 -bv root 2>&1 | head -1)
            DETAILS="Sendmail ($SENDMAIL_PATH): $SENDMAIL_VER"

            # SMF 상태 확인
            if command -v svcs >/dev/null 2>&1; then
                typeset SM_STATE=$(svcs -H sendmail 2>/dev/null | awk '{print $1}')
                if [ -n "$SM_STATE" ]; then
                    DETAILS="${DETAILS}
    Sendmail SMF 상태: $SM_STATE"
                fi
            fi
        fi

        # Postfix 확인
        if [ -x /usr/lib/postfix/postconf ] || [ -x /usr/sbin/postconf ] || [ -x /usr/local/sbin/postconf ]; then
            MAIL_FOUND="true"
            typeset POSTCONF_PATH=""
            if [ -x /usr/lib/postfix/postconf ]; then
                POSTCONF_PATH="/usr/lib/postfix/postconf"
            elif [ -x /usr/sbin/postconf ]; then
                POSTCONF_PATH="/usr/sbin/postconf"
            elif [ -x /usr/local/sbin/postconf ]; then
                POSTCONF_PATH="/usr/local/sbin/postconf"
            fi
            typeset POSTFIX_VER=$($POSTCONF_PATH 2>/dev/null | grep "mail_version" | head -1)
            DETAILS="${DETAILS}
    Postfix: $POSTFIX_VER"
        fi

        # Exim 확인
        if [ -x /usr/sbin/exim ] || [ -x /usr/local/sbin/exim ]; then
            MAIL_FOUND="true"
            typeset EXIM_PATH="/usr/sbin/exim"
            if [ -x /usr/local/sbin/exim ]; then
                EXIM_PATH="/usr/local/sbin/exim"
            fi
            typeset EXIM_VER=$($EXIM_PATH -bV 2>/dev/null | head -1)
            DETAILS="${DETAILS}
    Exim: $EXIM_VER"
        fi

        if [ "$MAIL_FOUND" = "true" ]; then
            RES="M"
            DESC="메일 서비스 버전 수동 확인 필요"
        else
            # 프로세스로 확인
            if is_process_running "sendmail" || is_process_running "postfix" || is_process_running "exim"; then
                RES="M"
                DESC="메일 서비스 프로세스 실행 중 (버전 확인 필요)"
                DETAILS="메일 프로세스: 실행 중"
            else
                RES="N/A"
                DESC="메일 서비스가 설치되지 않음"
                DETAILS="sendmail/postfix/exim: 미설치"
            fi
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check46() {
    local CODE="U-46"
    local CAT="서비스관리"
    local NAME="일반 사용자의 메일 서비스 실행 방지"
    local IMP="상"
    local STD="일반 사용자의 메일 서비스 실행 방지가 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset HAS_ISSUE="false"
        typeset DETAILS=""
        typeset MAIL_FOUND="false"

        # Sendmail 확인
        typeset SENDMAIL_PATH=""
        if [ -x /usr/sbin/sendmail ]; then
            SENDMAIL_PATH="/usr/sbin/sendmail"
        elif [ -x /usr/lib/sendmail ]; then
            SENDMAIL_PATH="/usr/lib/sendmail"
        fi

        if [ -n "$SENDMAIL_PATH" ]; then
            MAIL_FOUND="true"
            typeset PERM=$(get_file_perm "$SENDMAIL_PATH")
            DETAILS="$SENDMAIL_PATH: $PERM"

            # SUID 비트 + other 실행 권한 확인
            typeset SUID_BIT=$((PERM / 1000))
            if [ $((SUID_BIT & 4)) -ne 0 ]; then
                typeset OTHER_PERM=$((PERM % 10))
                if [ $((OTHER_PERM & 1)) -ne 0 ]; then
                    HAS_ISSUE="true"
                    DETAILS="${DETAILS}
    SUID 비트: 설정됨, other 실행 권한: 있음 (취약)"
                else
                    DETAILS="${DETAILS}
    SUID 비트: 설정됨, other 실행 권한: 없음 (양호)"
                fi
            else
                DETAILS="${DETAILS}
    SUID 비트: 미설정 (양호)"
            fi

            # sendmail.cf PrivacyOptions 확인
            typeset SENDMAIL_CF="/etc/mail/sendmail.cf"
            if [ -f "$SENDMAIL_CF" ]; then
                typeset PRIVACY=$(grep -i "^O PrivacyOptions" "$SENDMAIL_CF" 2>/dev/null)
                typeset PRIVACY_LOWER=$(printf "%s" "$PRIVACY" | tr 'A-Z' 'a-z')
                case "$PRIVACY_LOWER" in
                    *restrictqrun*)
                        DETAILS="${DETAILS}
    PrivacyOptions: restrictqrun 설정됨 (양호)"
                        ;;
                    *)
                        HAS_ISSUE="true"
                        DETAILS="${DETAILS}
    PrivacyOptions: restrictqrun 미설정 (취약)"
                        ;;
                esac
            fi
        fi

        # Postfix postsuper 확인
        if [ -x /usr/sbin/postsuper ]; then
            MAIL_FOUND="true"
            typeset PS_PERM=$(get_file_perm "/usr/sbin/postsuper")
            typeset PS_OTHER=$((PS_PERM % 10))
            DETAILS="${DETAILS}
    /usr/sbin/postsuper: $PS_PERM"
            if [ $((PS_OTHER & 1)) -ne 0 ]; then
                HAS_ISSUE="true"
                DETAILS="${DETAILS} (other 실행 권한 있음 - 취약)"
            else
                DETAILS="${DETAILS} (other 실행 권한 없음 - 양호)"
            fi
        fi

        # Exim exiqgrep 확인
        typeset EXIQGREP_PATH=""
        if [ -x /usr/sbin/exiqgrep ]; then
            EXIQGREP_PATH="/usr/sbin/exiqgrep"
        elif [ -x /usr/local/sbin/exiqgrep ]; then
            EXIQGREP_PATH="/usr/local/sbin/exiqgrep"
        fi
        if [ -n "$EXIQGREP_PATH" ]; then
            MAIL_FOUND="true"
            typeset EX_PERM=$(get_file_perm "$EXIQGREP_PATH")
            typeset EX_OTHER=$((EX_PERM % 10))
            DETAILS="${DETAILS}
    $EXIQGREP_PATH: $EX_PERM"
            if [ $((EX_OTHER & 1)) -ne 0 ]; then
                HAS_ISSUE="true"
                DETAILS="${DETAILS} (other 실행 권한 있음 - 취약)"
            else
                DETAILS="${DETAILS} (other 실행 권한 없음 - 양호)"
            fi
        fi

        if [ "$MAIL_FOUND" = "false" ]; then
            RES="N/A"
            DESC="메일 서비스가 설치되지 않음"
            DT="sendmail/postfix/exim: 미설치"
        elif [ "$HAS_ISSUE" = "true" ]; then
            RES="N"
            DESC="메일 서비스 보안 설정 미흡"
            DT="$DETAILS"
        else
            RES="Y"
            DESC="메일 서비스 보안 설정 양호"
            DT="$DETAILS"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check47() {
    local CODE="U-47"
    local CAT="서비스관리"
    local NAME="스팸 메일 릴레이 제한"
    local IMP="상"
    local STD="릴레이 제한이 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset DETAILS=""
        typeset MAIL_FOUND="false"

        # Sendmail 확인
        typeset SENDMAIL_CF="/etc/mail/sendmail.cf"
        if [ -f "$SENDMAIL_CF" ]; then
            MAIL_FOUND="true"
            typeset RELAY=$(grep -i "R\$\*" "$SENDMAIL_CF" 2>/dev/null | head -3)
            typeset RELAY_DOMAIN=$(grep -i "relay-domains" "$SENDMAIL_CF" 2>/dev/null | head -3)
            typeset PROMISCUOUS=$(grep -i "promiscuous_relay" "$SENDMAIL_CF" 2>/dev/null)
            DETAILS="sendmail.cf 릴레이 설정:
    $RELAY
    $RELAY_DOMAIN"
            if [ -n "$PROMISCUOUS" ]; then
                DETAILS="${DETAILS}
    promiscuous_relay: $PROMISCUOUS"
            fi

            # access 파일 확인
            if [ -f /etc/mail/access ]; then
                typeset ACCESS=$(grep -v "^#" /etc/mail/access 2>/dev/null | head -5)
                DETAILS="${DETAILS}
    /etc/mail/access:
    $ACCESS"
            fi
            RES="M"
            DESC="메일 릴레이 설정 수동 확인 필요"
        fi

        # Postfix 확인
        typeset POSTFIX_CF="/etc/postfix/main.cf"
        if [ -f "$POSTFIX_CF" ]; then
            MAIL_FOUND="true"
            typeset PF_RELAY=$(grep -E "^mynetworks|^smtpd_recipient_restrictions" "$POSTFIX_CF" 2>/dev/null)
            DETAILS="${DETAILS}
    postfix main.cf:
    $PF_RELAY"
            RES="M"
            DESC="메일 릴레이 설정 수동 확인 필요"
        fi

        # Exim 확인
        typeset EXIM_CONF=""
        for f in /etc/exim/exim.conf /etc/exim4/exim4.conf /usr/local/etc/exim/exim.conf; do
            if [ -f "$f" ]; then
                EXIM_CONF="$f"
                break
            fi
        done
        if [ -n "$EXIM_CONF" ]; then
            MAIL_FOUND="true"
            typeset EX_RELAY=$(grep -E "relay_from_hosts|hosts =" "$EXIM_CONF" 2>/dev/null | head -5)
            DETAILS="${DETAILS}
    exim ($EXIM_CONF):
    $EX_RELAY"
            RES="M"
            DESC="메일 릴레이 설정 수동 확인 필요"
        fi

        if [ "$MAIL_FOUND" = "false" ]; then
            RES="N/A"
            DESC="메일 서비스 설정 파일 없음"
            DETAILS="sendmail.cf/main.cf/exim.conf: 없음"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check48() {
    local CODE="U-48"
    local CAT="서비스관리"
    local NAME="expn, vrfy 명령어 제한"
    local IMP="중"
    local STD="noexpn, novrfy 옵션이 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset DETAILS=""
        typeset MAIL_FOUND="false"

        # Sendmail 확인
        typeset SENDMAIL_CF="/etc/mail/sendmail.cf"
        if [ -f "$SENDMAIL_CF" ]; then
            MAIL_FOUND="true"
            typeset PRIVACY=$(grep -i "^O PrivacyOptions" "$SENDMAIL_CF" 2>/dev/null)
            DETAILS="sendmail PrivacyOptions:
    $PRIVACY"

            typeset PRIVACY_LOWER=$(printf "%s" "$PRIVACY" | tr 'A-Z' 'a-z')
            case "$PRIVACY_LOWER" in
                *goaway*)
                    RES="Y"
                    DESC="expn, vrfy 명령어가 제한됨 (goaway)"
                    ;;
                *noexpn*)
                    case "$PRIVACY_LOWER" in
                        *novrfy*)
                            RES="Y"
                            DESC="expn, vrfy 명령어가 제한됨"
                            ;;
                        *)
                            RES="N"
                            DESC="vrfy 명령어가 허용됨 (novrfy 미설정)"
                            ;;
                    esac
                    ;;
                *novrfy*)
                    RES="N"
                    DESC="expn 명령어가 허용됨 (noexpn 미설정)"
                    ;;
                *)
                    RES="N"
                    DESC="expn, vrfy 명령어가 허용됨"
                    ;;
            esac
        fi

        # Postfix 확인
        typeset POSTFIX_CF="/etc/postfix/main.cf"
        if [ -f "$POSTFIX_CF" ]; then
            MAIL_FOUND="true"
            typeset VRFY=$(grep -i "^disable_vrfy_command" "$POSTFIX_CF" 2>/dev/null)
            DETAILS="${DETAILS}
    postfix disable_vrfy_command:
    $VRFY"

            typeset VRFY_LOWER=$(printf "%s" "$VRFY" | tr 'A-Z' 'a-z')
            case "$VRFY_LOWER" in
                *yes*)
                    if [ -z "$RES" ] || [ "$RES" = "Y" ]; then
                        RES="Y"
                        DESC="vrfy 명령어가 제한됨"
                    fi
                    ;;
                *)
                    RES="N"
                    DESC="vrfy 명령어가 허용됨 (postfix)"
                    ;;
            esac
        fi

        # Exim 확인
        typeset EXIM_CONF=""
        for f in /etc/exim/exim.conf /etc/exim4/exim4.conf /usr/local/etc/exim/exim.conf; do
            if [ -f "$f" ]; then
                EXIM_CONF="$f"
                break
            fi
        done
        if [ -n "$EXIM_CONF" ]; then
            MAIL_FOUND="true"
            typeset EX_VRFY=$(grep -E "acl_smtp_vrfy|acl_smtp_expn" "$EXIM_CONF" 2>/dev/null)
            DETAILS="${DETAILS}
    exim vrfy/expn:
    $EX_VRFY"
            if printf "%s" "$EX_VRFY" | grep -qi "accept"; then
                RES="N"
                DESC="expn/vrfy 명령어가 허용됨 (exim)"
            fi
        fi

        if [ "$MAIL_FOUND" = "false" ]; then
            RES="N/A"
            DESC="메일 서비스 설정 파일 없음"
            DETAILS="sendmail.cf/main.cf/exim.conf: 없음"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check49() {
    local CODE="U-49"
    local CAT="서비스관리"
    local NAME="DNS 보안 버전 패치"
    local IMP="상"
    local STD="주기적으로 패치를 관리하는 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset DETAILS=""
        typeset DNS_RUNNING="false"

        # SMF (Solaris 10+) DNS/BIND 서비스 확인
        if command -v svcs >/dev/null 2>&1; then
            typeset BIND_STATUS=$(svcs -a 2>/dev/null | grep -i bind)
            typeset DNS_STATUS=$(svcs -a 2>/dev/null | grep -i dns)
            if [ -n "$BIND_STATUS" ]; then
                case "$BIND_STATUS" in
                    *online*)
                        DNS_RUNNING="true"
                        ;;
                esac
                DETAILS="SMF BIND:
    $BIND_STATUS"
            fi
            if [ -n "$DNS_STATUS" ]; then
                case "$DNS_STATUS" in
                    *online*)
                        DNS_RUNNING="true"
                        ;;
                esac
                DETAILS="${DETAILS}
    SMF DNS:
    $DNS_STATUS"
            fi
        fi

        # named 프로세스 확인
        if is_process_running "named"; then
            DNS_RUNNING="true"
            DETAILS="${DETAILS}
    named 프로세스: 실행 중"
        fi

        if [ "$DNS_RUNNING" = "true" ]; then
            # BIND 버전 확인
            typeset NAMED_VER=""
            if [ -x /usr/sbin/named ]; then
                NAMED_VER=$(/usr/sbin/named -v 2>/dev/null)
            elif [ -x /usr/local/sbin/named ]; then
                NAMED_VER=$(/usr/local/sbin/named -v 2>/dev/null)
            fi
            DETAILS="${DETAILS}
    BIND 버전: ${NAMED_VER:-확인 필요}"
            RES="M"
            DESC="DNS 서비스 버전 수동 확인 필요"
        else
            RES="N/A"
            DESC="DNS 서비스가 실행되지 않음"
            if [ -z "$DETAILS" ]; then
                DETAILS="named: 미실행"
            fi
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check50() {
    local CODE="U-50"
    local CAT="서비스관리"
    local NAME="DNS ZoneTransfer 설정"
    local IMP="상"
    local STD="Zone Transfer를 허가된 사용자에게만 허용한 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset NAMED_CONF=""
        for f in /etc/named.conf /etc/bind/named.conf /usr/local/etc/named.conf; do
            if [ -f "$f" ]; then
                NAMED_CONF="$f"
                break
            fi
        done

        if [ -z "$NAMED_CONF" ]; then
            # named.boot 확인 (구버전)
            typeset NAMED_BOOT=""
            for f in /etc/named.boot /etc/bind/named.boot; do
                if [ -f "$f" ]; then
                    NAMED_BOOT="$f"
                    break
                fi
            done

            if [ -n "$NAMED_BOOT" ]; then
                typeset XFRNETS=$(grep -i "xfrnets" "$NAMED_BOOT" 2>/dev/null)
                if [ -n "$XFRNETS" ]; then
                    RES="M"
                    DESC="Zone Transfer 설정 수동 확인 필요"
                    DT="$NAMED_BOOT:
    $XFRNETS"
                else
                    RES="N"
                    DESC="Zone Transfer 제한 미설정 (named.boot)"
                    DT="xfrnets: 미설정"
                fi
            else
                RES="N/A"
                DESC="DNS 설정 파일이 없음"
                DT="named.conf/named.boot: 없음"
            fi
        else
            typeset ALLOW_TRANSFER=$(grep -i "allow-transfer" "$NAMED_CONF" 2>/dev/null)

            if [ -z "$ALLOW_TRANSFER" ]; then
                RES="N"
                DESC="Zone Transfer 제한 미설정"
                DT="$NAMED_CONF: allow-transfer 미설정"
            else
                typeset ALLOW_LOWER=$(printf "%s" "$ALLOW_TRANSFER" | tr 'A-Z' 'a-z')
                case "$ALLOW_LOWER" in
                    *none*)
                        RES="Y"
                        DESC="Zone Transfer가 제한됨 (none)"
                        DT="$ALLOW_TRANSFER"
                        ;;
                    *)
                        RES="M"
                        DESC="Zone Transfer 설정 수동 확인 필요"
                        DT="$NAMED_CONF:
    $ALLOW_TRANSFER"
                        ;;
                esac
            fi
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check51() {
    local CODE="U-51"
    local CAT="서비스관리"
    local NAME="DNS 서비스의 취약한 동적 업데이트 설정 금지"
    local IMP="중"
    local STD="DNS 서비스의 동적 업데이트 기능이 비활성화되었거나, 활성화 시 적절한 접근통제를 수행하고 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

    typeset NAMED_CONF="/etc/named.conf"
    if [ ! -f "$NAMED_CONF" ]; then
        NAMED_CONF="/etc/bind/named.conf"
    fi

    if [ ! -f "$NAMED_CONF" ]; then
        RES="N/A"
        DESC="DNS 설정 파일이 없음"
        DT="named.conf: 없음"
    else
        typeset ALLOW_UPDATE=$(grep -i "allow-update" "$NAMED_CONF" 2>/dev/null)

        if [ -z "$ALLOW_UPDATE" ]; then
            RES="Y"
            DESC="동적 업데이트가 설정되지 않음"
            DT="allow-update: not set"
        else
            typeset UPDATE_LOWER=$(printf "%s" "$ALLOW_UPDATE" | tr 'A-Z' 'a-z')
            case "$UPDATE_LOWER" in
                *none*)
                    RES="Y"
                    DESC="동적 업데이트가 제한됨"
                    DT="$ALLOW_UPDATE"
                    ;;
                *)
                    RES="M"
                    DESC="동적 업데이트 설정 수동 확인 필요"
                    DT="$ALLOW_UPDATE"
                    ;;
            esac
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check52() {
    local CODE="U-52"
    local CAT="서비스관리"
    local NAME="Telnet 서비스 비활성화"
    local IMP="중"
    local STD="원격 접속 시 Telnet 프로토콜을 비활성화하고 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset RUNNING="false"
        typeset DETAILS=""

        # SMF (Solaris 10+) 확인
        if command -v svcs >/dev/null 2>&1; then
            typeset TELNET_STATE=$(get_smf_state "svc:/network/telnet:default" 2>/dev/null)
            if [ -n "$TELNET_STATE" ]; then
                case "$TELNET_STATE" in
                    online)
                        RUNNING="true"
                        DETAILS="SMF telnet: online"
                        ;;
                    *)
                        DETAILS="SMF telnet: $TELNET_STATE"
                        ;;
                esac
            fi
        fi

        # inetadm 확인
        if command -v inetadm >/dev/null 2>&1; then
            typeset TELNET_SVC=$(inetadm 2>/dev/null | grep -i telnet | grep -v "^#")
            if [ -n "$TELNET_SVC" ]; then
                case "$TELNET_SVC" in
                    *enabled*)
                        RUNNING="true"
                        DETAILS="${DETAILS}
    inetadm telnet: enabled"
                        ;;
                esac
            fi
        fi

        # inetd.conf 확인 (Solaris 9 이하)
        if [ -f /etc/inetd.conf ]; then
            if grep -q "^telnet" /etc/inetd.conf 2>/dev/null; then
                RUNNING="true"
                DETAILS="${DETAILS}
    inetd.conf telnet: enabled"
            fi
        fi

        # 프로세스 확인
        if ps -ef 2>/dev/null | grep -q "[i]n.telnetd"; then
            RUNNING="true"
            DETAILS="${DETAILS}
    telnetd 프로세스: 실행 중"
        fi

        if [ "$RUNNING" = "true" ]; then
            RES="N"
            DESC="Telnet 서비스가 활성화됨"
        else
            RES="Y"
            DESC="Telnet 서비스가 비활성화됨"
            if [ -z "$DETAILS" ]; then
                DETAILS="telnet: 미실행"
            fi
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check53() {
    local CODE="U-53"
    local CAT="서비스관리"
    local NAME="FTP 서비스 정보 노출 제한"
    local IMP="하"
    local STD="FTP 접속 배너에 노출되는 정보가 없는 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset DETAILS=""

        # vsftpd 확인
        if [ -f /etc/vsftpd/vsftpd.conf ] || [ -f /etc/vsftpd.conf ]; then
            typeset VSFTPD_CONF="/etc/vsftpd/vsftpd.conf"
            if [ -f /etc/vsftpd.conf ]; then
                VSFTPD_CONF="/etc/vsftpd.conf"
            fi
            typeset BANNER=$(grep -i "ftpd_banner" "$VSFTPD_CONF" 2>/dev/null)
            DETAILS="vsftpd 배너: ${BANNER:-기본값}"
            RES="M"
            DESC="FTP 배너 설정 수동 확인 필요"
        # proftpd 확인
        elif [ -f /etc/proftpd.conf ]; then
            typeset BANNER=$(grep -i "ServerIdent" /etc/proftpd.conf 2>/dev/null)
            DETAILS="proftpd ServerIdent: ${BANNER:-기본값}"
            RES="M"
            DESC="FTP 배너 설정 수동 확인 필요"
        # Solaris 기본 FTP 배너 확인
        elif [ -f /etc/default/ftpd ]; then
            typeset BANNER=$(grep -i "BANNER" /etc/default/ftpd 2>/dev/null)
            DETAILS="Solaris ftpd BANNER: ${BANNER:-기본값}"
            RES="M"
            DESC="FTP 배너 설정 수동 확인 필요"
        elif [ -f /etc/ftpd/banner.msg ]; then
            typeset BANNER=$(head -3 /etc/ftpd/banner.msg 2>/dev/null)
            DETAILS="FTP banner.msg:
    $BANNER"
            RES="M"
            DESC="FTP 배너 설정 수동 확인 필요"
        else
            RES="N/A"
            DESC="FTP 서비스 설정 파일 없음"
            DETAILS="FTP 설정 파일: 없음"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check54() {
    local CODE="U-54"
    local CAT="서비스관리"
    local NAME="암호화되지 않는 FTP 서비스 비활성화"
    local IMP="중"
    local STD="암호화되지 않은 FTP 서비스가 비활성화된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset RUNNING="false"
        typeset DETAILS=""

        # SMF (Solaris 10+) FTP 서비스 확인
        if command -v inetadm >/dev/null 2>&1; then
            typeset FTP_SVC=$(inetadm 2>/dev/null | grep -i ftp | grep -v "^#")
            if [ -n "$FTP_SVC" ]; then
                case "$FTP_SVC" in
                    *enabled*)
                        RUNNING="true"
                        DETAILS="SMF FTP: enabled
    $FTP_SVC"
                        ;;
                esac
            fi
        fi

        # svcs로 vsftpd/proftpd SMF 확인
        if command -v svcs >/dev/null 2>&1; then
            typeset VSFTPD_STATE=$(get_smf_state "svc:/network/ftp:default" 2>/dev/null)
            if [ "$VSFTPD_STATE" = "online" ]; then
                RUNNING="true"
                DETAILS="${DETAILS}
    FTP (SMF): online"
            fi
        fi

        # FTP 프로세스 확인
        if ps -ef 2>/dev/null | grep -qE "[v]sftpd|[p]roftpd|[i]n.ftpd|[f]tpd"; then
            RUNNING="true"
            DETAILS="${DETAILS}
    FTP 프로세스: 실행 중"
        fi

        if [ "$RUNNING" = "true" ]; then
            # SSL/TLS 설정 확인
            if [ -f /etc/vsftpd/vsftpd.conf ] || [ -f /etc/vsftpd.conf ]; then
                typeset VSFTPD_CONF="/etc/vsftpd/vsftpd.conf"
                if [ -f /etc/vsftpd.conf ]; then
                    VSFTPD_CONF="/etc/vsftpd.conf"
                fi
                typeset SSL_ENABLE=$(grep -i "ssl_enable" "$VSFTPD_CONF" 2>/dev/null)
                typeset SSL_LOWER=$(printf "%s" "$SSL_ENABLE" | tr 'A-Z' 'a-z')
                case "$SSL_LOWER" in
                    *yes*)
                        RES="Y"
                        DESC="FTP SSL/TLS가 활성화됨"
                        ;;
                    *)
                        RES="N"
                        DESC="FTP가 암호화 없이 실행 중"
                        ;;
                esac
            else
                RES="N"
                DESC="FTP가 암호화 없이 실행 중"
            fi
        else
            RES="Y"
            DESC="FTP 서비스가 비활성화됨"
            DETAILS="FTP: 미실행"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check55() {
    local CODE="U-55"
    local CAT="서비스관리"
    local NAME="FTP 계정 shell 제한"
    local IMP="중"
    local STD="FTP 계정에 /bin/false(/sbin/nologin) 쉘이 부여된 경우"
    local RES=""
    local DESC=""
    local DT=""

    # ftp 계정 쉘 확인
    typeset FTP_SHELL=$(grep "^ftp:" /etc/passwd 2>/dev/null | cut -d: -f7)

    if [ -z "$FTP_SHELL" ]; then
        RES="N/A"
        DESC="ftp 계정이 존재하지 않음"
        DT="ftp 계정: 없음"
    else
        case "$FTP_SHELL" in
            */nologin|*/false)
                RES="Y"
                DESC="ftp 계정에 쉘이 제한됨"
                DT="ftp 쉘: $FTP_SHELL"
                ;;
            *)
                RES="N"
                DESC="ftp 계정에 쉘이 부여됨"
                DT="ftp 쉘: $FTP_SHELL"
                ;;
        esac
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check56() {
    local CODE="U-56"
    local CAT="서비스관리"
    local NAME="FTP 서비스 접근 제어 설정"
    local IMP="하"
    local STD="특정 IP주소 또는 호스트에서만 FTP 서버에 접속할 수 있도록 접근 제어 설정을 적용한 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset DETAILS=""
        typeset HAS_CONTROL="false"

        # hosts.allow/deny 확인
        typeset HOSTS_ALLOW_FTP=$(grep -iE "vsftpd|proftpd|ftpd|in.ftpd" /etc/hosts.allow 2>/dev/null)
        if [ -n "$HOSTS_ALLOW_FTP" ]; then
            HAS_CONTROL="true"
            DETAILS="hosts.allow: FTP 설정 존재
    "
        fi

        typeset HOSTS_DENY_FTP=$(grep -iE "vsftpd|proftpd|ftpd|in.ftpd" /etc/hosts.deny 2>/dev/null)
        if [ -n "$HOSTS_DENY_FTP" ]; then
            HAS_CONTROL="true"
            DETAILS="${DETAILS}hosts.deny: FTP 설정 존재
    "
        fi

        # vsftpd tcp_wrappers 확인
        if [ -f /etc/vsftpd/vsftpd.conf ] || [ -f /etc/vsftpd.conf ]; then
            typeset VSFTPD_CONF="/etc/vsftpd/vsftpd.conf"
            if [ -f /etc/vsftpd.conf ]; then
                VSFTPD_CONF="/etc/vsftpd.conf"
            fi
            typeset TCP_WRAP=$(grep -i "tcp_wrappers" "$VSFTPD_CONF" 2>/dev/null)
            DETAILS="${DETAILS}vsftpd tcp_wrappers: ${TCP_WRAP:-not set}"
        fi

        # Solaris ftpusers 파일 존재 여부 확인
        if [ -f /etc/ftpd/ftpusers ] || [ -f /etc/ftpusers ]; then
            HAS_CONTROL="true"
            DETAILS="${DETAILS}
    ftpusers 파일: 존재"
        fi

        if [ "$HAS_CONTROL" = "true" ]; then
            RES="Y"
            DESC="FTP 접근 제어가 설정됨"
        else
            RES="M"
            DESC="FTP 접근 제어 수동 확인 필요"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check57() {
    local CODE="U-57"
    local CAT="서비스관리"
    local NAME="Ftpusers 파일 설정"
    local IMP="중"
    local STD="root 계정 접속을 차단한 경우"
    local RES=""
    local DESC=""
    local DT=""

        # Solaris 기본 경로: /etc/ftpd/ftpusers
        typeset FTPUSERS="/etc/ftpd/ftpusers"
        if [ ! -f "$FTPUSERS" ]; then
            FTPUSERS="/etc/vsftpd/ftpusers"
        fi
        if [ ! -f "$FTPUSERS" ]; then
            FTPUSERS="/etc/ftpusers"
        fi

        if [ ! -f "$FTPUSERS" ]; then
            RES="N/A"
            DESC="ftpusers 파일이 없음"
            DT="ftpusers: 없음"
        else
            typeset ROOT_DENIED=$(grep "^root" "$FTPUSERS" 2>/dev/null)
            typeset CONTENT=$(head -10 "$FTPUSERS" 2>/dev/null)

            if [ -n "$ROOT_DENIED" ]; then
                RES="Y"
                DESC="root 계정이 ftpusers에 등록됨"
            else
                RES="N"
                DESC="root 계정이 ftpusers에 미등록"
            fi
            DT="$FTPUSERS:
    $CONTENT"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check58() {
    local CODE="U-58"
    local CAT="서비스관리"
    local NAME="불필요한 SNMP 서비스 구동 점검"
    local IMP="중"
    local STD="SNMP 서비스를 사용하지 않는 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset RUNNING="false"
        typeset DETAILS=""

        # SMF (Solaris 10+) SNMP 서비스 확인
        if command -v svcs >/dev/null 2>&1; then
            # snmpdx (Solaris 10 legacy)
            typeset SNMPDX_STATUS=$(get_smf_state "svc:/application/management/snmpdx" 2>/dev/null)
            if [ "$SNMPDX_STATUS" = "online" ]; then
                RUNNING="true"
                DETAILS="snmpdx (SMF): online"
            fi
            # net-snmp (Solaris 11)
            typeset NETSNMP_STATUS=$(get_smf_state "svc:/application/management/net-snmp" 2>/dev/null)
            if [ "$NETSNMP_STATUS" = "online" ]; then
                RUNNING="true"
                DETAILS="${DETAILS}
    net-snmp (SMF): online"
            fi
        fi

        # snmpd 프로세스 확인
        if ps -ef 2>/dev/null | grep -q "[s]nmpd"; then
            RUNNING="true"
            DETAILS="${DETAILS}
    snmpd 프로세스: 실행 중"
        fi

        if [ "$RUNNING" = "true" ]; then
            RES="M"
            DESC="SNMP 서비스 사용 여부 수동 확인 필요"
        else
            RES="Y"
            DESC="SNMP 서비스가 비활성화됨"
            DETAILS="snmpd: 미실행"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check59() {
    local CODE="U-59"
    local CAT="서비스관리"
    local NAME="안전한 SNMP 버전 사용"
    local IMP="상"
    local STD="SNMP 서비스를 v3 이상으로 사용하는 경우"
    local RES=""
    local DESC=""
    local DT=""

        # Solaris 11: /etc/net-snmp/snmp/snmpd.conf
        # Solaris 10: /etc/snmp/conf/snmpd.conf or /etc/sma/snmp/snmpd.conf
        typeset SNMP_CONF="/etc/net-snmp/snmp/snmpd.conf"
        if [ ! -f "$SNMP_CONF" ]; then
            SNMP_CONF="/etc/snmp/conf/snmpd.conf"
        fi
        if [ ! -f "$SNMP_CONF" ]; then
            SNMP_CONF="/etc/sma/snmp/snmpd.conf"
        fi

        if [ ! -f "$SNMP_CONF" ]; then
            if ! ps -ef 2>/dev/null | grep -q "[s]nmpd"; then
                RES="N/A"
                DESC="SNMP 서비스가 사용되지 않음"
                DT="snmpd.conf: 없음, snmpd: 미실행"
            else
                RES="M"
                DESC="SNMP 설정 수동 확인 필요"
                DT="snmpd.conf: 없음"
            fi
        else
            typeset V3_CONFIG=$(grep -iE "^rouser|^rwuser|^createUser" "$SNMP_CONF" 2>/dev/null)
            typeset V1V2_CONFIG=$(grep -iE "^rocommunity|^rwcommunity|^read-community|^write-community" "$SNMP_CONF" 2>/dev/null)

            if [ -n "$V3_CONFIG" ] && [ -z "$V1V2_CONFIG" ]; then
                RES="Y"
                DESC="SNMPv3만 사용 중"
                DT="SNMPv3 설정:
    $V3_CONFIG"
            elif [ -n "$V1V2_CONFIG" ]; then
                RES="N"
                DESC="취약한 SNMP 버전(v1/v2c) 사용 중"
                DT="v1/v2c 설정:
    $V1V2_CONFIG"
            else
                RES="M"
                DESC="SNMP 버전 수동 확인 필요"
                DT="설정 확인 필요"
            fi
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check60() {
    local CODE="U-60"
    local CAT="서비스관리"
    local NAME="SNMP Community String 복잡성 설정"
    local IMP="중"
    local STD="SNMP Community String 기본값인 “public”, “private”이 아닌 영문자, 숫자 포함 10자리 이상 또는 영문자, 숫자, 특수문자 포함 8자리 이상인 경우"
    local RES=""
    local DESC=""
    local DT=""

    # Solaris 11: /etc/net-snmp/snmp/snmpd.conf
    # Solaris 10: /etc/snmp/conf/snmpd.conf or /etc/sma/snmp/snmpd.conf
    typeset SNMP_CONF="/etc/net-snmp/snmp/snmpd.conf"
    if [ ! -f "$SNMP_CONF" ]; then
        SNMP_CONF="/etc/snmp/conf/snmpd.conf"
    fi
    if [ ! -f "$SNMP_CONF" ]; then
        SNMP_CONF="/etc/sma/snmp/snmpd.conf"
    fi

    typeset WEAK_STRINGS="public private"

    if [ ! -f "$SNMP_CONF" ]; then
        RES="N/A"
        DESC="SNMP 설정 파일이 없음"
        DT="snmpd.conf: 없음"
    else
        # rocommunity/rwcommunity (Solaris 10+) 또는 read-community/write-community (Solaris 9)
        typeset COMMUNITIES=$(grep -iE "^rocommunity|^rwcommunity|^read-community|^write-community" "$SNMP_CONF" 2>/dev/null | awk '{print $2}')
        typeset HAS_WEAK="false"

        for comm in $COMMUNITIES; do
            for weak in $WEAK_STRINGS; do
                if [ "$comm" = "$weak" ]; then
                    HAS_WEAK="true"
                    break
                fi
            done
        done

        if [ -z "$COMMUNITIES" ]; then
            RES="Y"
            DESC="Community String 미사용 (SNMPv3 사용)"
            DT="Community: 설정 없음"
        elif [ "$HAS_WEAK" = "true" ]; then
            RES="N"
            DESC="취약한 Community String 사용 중"
            DT="Community: $COMMUNITIES"
        else
            RES="Y"
            DESC="Community String이 복잡하게 설정됨"
            DT="Community: $COMMUNITIES"
        fi
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check61() {
    local CODE="U-61"
    local CAT="서비스관리"
    local NAME="SNMP Access Control 설정"
    local IMP="상"
    local STD="SNMP 서비스에 접근 제어 설정이 되어 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset SNMP_CONF="/etc/net-snmp/snmp/snmpd.conf"
        if [ ! -f "$SNMP_CONF" ]; then
            SNMP_CONF="/etc/snmp/conf/snmpd.conf"
        fi
        if [ ! -f "$SNMP_CONF" ]; then
            SNMP_CONF="/etc/sma/snmp/snmpd.conf"
        fi

        if [ ! -f "$SNMP_CONF" ]; then
            RES="N/A"
            DESC="SNMP 설정 파일이 없음"
            DT="snmpd.conf: 없음"
        else
            typeset DETAILS=""
            typeset HAS_ISSUE="false"

            # 접근 제어 설정 확인
            typeset ACCESS_CONTROL=$(grep -iE "^com2sec|^group|^access|^view" "$SNMP_CONF" 2>/dev/null | head -10)
            if [ -n "$ACCESS_CONTROL" ]; then
                DETAILS="접근 제어 설정:
    $ACCESS_CONTROL"
            fi

            # rocommunity/rwcommunity 네트워크 제한 확인
            typeset ROCOMM=$(grep -E "^rocommunity[[:space:]]" "$SNMP_CONF" 2>/dev/null)
            typeset RWCOMM=$(grep -E "^rwcommunity[[:space:]]" "$SNMP_CONF" 2>/dev/null)

            if [ -n "$ROCOMM" ] || [ -n "$RWCOMM" ]; then
                DETAILS="${DETAILS}
    --- Community 설정 ---"
                if [ -n "$ROCOMM" ]; then
                    DETAILS="${DETAILS}
    $ROCOMM"
                fi
                if [ -n "$RWCOMM" ]; then
                    DETAILS="${DETAILS}
    $RWCOMM"
                fi

                # 네트워크 제한 없이 설정된 경우 확인
                # rocommunity <string> [IP/network] - 필드가 2개 이하이면 네트워크 제한 없음
                typeset NO_RESTRICT=$(printf "%s\n%s\n" "$ROCOMM" "$RWCOMM" | grep -v "^$" | awk 'NF<=2{print}')
                if [ -n "$NO_RESTRICT" ]; then
                    HAS_ISSUE="true"
                fi
            fi

            if [ "$HAS_ISSUE" = "true" ]; then
                RES="N"
                DESC="SNMP community 네트워크 제한 미설정"
            elif [ -n "$ACCESS_CONTROL" ]; then
                RES="M"
                DESC="SNMP 접근 제어 수동 확인 필요"
            else
                RES="N"
                DESC="SNMP 접근 제어 미설정"
            fi
            DT="$DETAILS"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check62() {
    local CODE="U-62"
    local CAT="서비스관리"
    local NAME="로그인 시 경고 메시지 설정"
    local IMP="하"
    local STD="서버 및 Telnet, FTP, SMTP, DNS 서비스에 로그온 시 경고 메시지가 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset BANNER_FILES="/etc/motd /etc/issue /etc/issue.net"
        typeset HAS_BANNER="false"
        typeset DETAILS=""

        for file in $BANNER_FILES; do
            if [ -f "$file" ] && [ -s "$file" ]; then
                typeset CONTENT=$(head -3 "$file" 2>/dev/null)
                DETAILS="${DETAILS}${file}:
    $CONTENT

    "
                HAS_BANNER="true"
            fi
        done

        # SSH 배너 확인
        typeset SSH_BANNER=$(grep -i "^Banner" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
        if [ -n "$SSH_BANNER" ] && [ "$SSH_BANNER" != "none" ]; then
            DETAILS="${DETAILS}SSH Banner: $SSH_BANNER"
            HAS_BANNER="true"
        fi

        # Solaris Telnet 배너 확인
        if [ -f /etc/default/telnetd ]; then
            typeset TELNET_BANNER=$(grep -i "^BANNER" /etc/default/telnetd 2>/dev/null)
            if [ -n "$TELNET_BANNER" ]; then
                DETAILS="${DETAILS}
    Telnet BANNER: $TELNET_BANNER"
                HAS_BANNER="true"
            fi
        fi

        if [ "$HAS_BANNER" = "true" ]; then
            RES="Y"
            DESC="로그인 경고 메시지가 설정됨"
        else
            RES="N"
            DESC="로그인 경고 메시지가 미설정"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check63() {
    local CODE="U-63"
    local CAT="서비스관리"
    local NAME="sudo 명령어 접근 관리"
    local IMP="중"
    local STD="/etc/sudoers 파일 소유자가 root이고, 파일 권한이 640인 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset SUDOERS="/etc/sudoers"

        if [ ! -f "$SUDOERS" ]; then
            RES="N/A"
            DESC="sudoers 파일이 없음"
            DT="$SUDOERS: 없음"
        else
            typeset HAS_ISSUE="false"
            typeset DETAILS=""

            # 파일 권한 및 소유자 확인
            typeset OWNER=$(get_file_owner "$SUDOERS")
            typeset PERM=$(get_file_perm "$SUDOERS")

            if [ "$OWNER" != "root" ]; then
                HAS_ISSUE="true"
                DETAILS="소유자: $OWNER (취약 - root 아님)
    "
            else
                DETAILS="소유자: $OWNER (양호)
    "
            fi

            if [ "$PERM" -gt 640 ] 2>/dev/null; then
                HAS_ISSUE="true"
                DETAILS="${DETAILS}권한: $PERM (취약 - 640 초과)
    "
            else
                DETAILS="${DETAILS}권한: $PERM (양호)
    "
            fi

            # NOPASSWD 또는 ALL 권한 확인
            typeset NOPASSWD=$(grep -v "^#" "$SUDOERS" 2>/dev/null | grep "NOPASSWD")
            typeset ALL_ALL=$(grep -v "^#" "$SUDOERS" 2>/dev/null | grep "ALL=(ALL)")

            typeset NOPASSWD_MSG="없음"
            typeset ALL_MSG="없음"
            if [ -n "$NOPASSWD" ]; then
                NOPASSWD_MSG="있음"
            fi
            if [ -n "$ALL_ALL" ]; then
                ALL_MSG="있음"
            fi

            DETAILS="${DETAILS}NOPASSWD 설정: $NOPASSWD_MSG
    ALL 권한: $ALL_MSG"

            if [ "$HAS_ISSUE" = "true" ]; then
                RES="N"
                DESC="sudoers 파일 권한/소유자 부적절"
            else
                RES="M"
                DESC="sudo 설정 수동 확인 필요"
            fi
            DT="$DETAILS"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check64() {
    local CODE="U-64"
    local CAT="패치관리"
    local NAME="주기적 보안 패치 및 벤더 권고사항 적용"
    local IMP="상"
    local STD="패치 적용 정책을 수립하여 주기적으로 패치 관리를 하고 있으며, 패치 관련 내용을 확인하고 적용하였을 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset DETAILS=""

        # OS 정보
        typeset OS_VER=$(uname -r 2>/dev/null)
        typeset OS_NAME=$(uname -s 2>/dev/null)
        typeset KERNEL=$(uname -v 2>/dev/null)

        DETAILS="OS: $OS_NAME $OS_VER
    Kernel: $KERNEL
    "

        # Solaris 패치 정보 확인 (showrev -p)
        if command -v showrev >/dev/null 2>&1; then
            typeset PATCH_COUNT=$(showrev -p 2>/dev/null | wc -l | awk '{print $1}')
            typeset LAST_PATCHES=$(showrev -p 2>/dev/null | tail -3)
            DETAILS="${DETAILS}설치된 패치 수: ${PATCH_COUNT:-확인불가}
    최근 패치:
    ${LAST_PATCHES:-없음}
    "
        fi

        # pkg 정보 확인 (Solaris 11+)
        if command -v pkg >/dev/null 2>&1; then
            typeset PKG_UPDATE_COUNT=$(pkg list -u 2>/dev/null | wc -l | awk '{print $1}')
            DETAILS="${DETAILS}업데이트 가능 패키지: ${PKG_UPDATE_COUNT:-확인불가}개
    "
            typeset PKG_ENTIRE=$(pkg list entire 2>/dev/null | head -1)
            if [ -n "$PKG_ENTIRE" ]; then
                DETAILS="${DETAILS}entire 패키지: $PKG_ENTIRE"
            fi
        fi

        RES="M"
        DESC="보안 패치 적용 여부 수동 확인 필요"
        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check65() {
    local CODE="U-65"
    local CAT="로그관리"
    local NAME="NTP 및 시각 동기화 설정"
    local IMP="중"
    local STD="NTP 및 시각 동기화 설정이 기준에 따라 적용된 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset RUNNING="false"
        typeset DETAILS=""

        # SMF (Solaris 10+) NTP 서비스 확인
        if command -v svcs >/dev/null 2>&1; then
            typeset NTP_STATUS=$(svcs -H ntp 2>/dev/null)
            if [ -n "$NTP_STATUS" ]; then
                case "$NTP_STATUS" in
                    *online*)
                        RUNNING="true"
                        DETAILS="NTP (SMF): online
    $NTP_STATUS"
                        ;;
                    *)
                        DETAILS="NTP (SMF):
    $NTP_STATUS"
                        ;;
                esac
            fi
        fi

        # xntpd/ntpd 프로세스 확인
        if ps -ef 2>/dev/null | grep -qE "[x]ntpd|[n]tpd"; then
            RUNNING="true"
            DETAILS="${DETAILS}
    NTP 프로세스: 실행 중"
        fi

        # ntp.conf 확인 (Solaris: /etc/inet/ntp.conf 또는 /etc/ntp.conf)
        typeset NTP_CONF=""
        if [ -f /etc/inet/ntp.conf ]; then
            NTP_CONF="/etc/inet/ntp.conf"
        elif [ -f /etc/ntp.conf ]; then
            NTP_CONF="/etc/ntp.conf"
        fi

        if [ -n "$NTP_CONF" ]; then
            typeset NTP_SERVERS=$(grep "^server" "$NTP_CONF" 2>/dev/null | head -3)
            if [ -n "$NTP_SERVERS" ]; then
                DETAILS="${DETAILS}
    NTP 설정 ($NTP_CONF):
    $NTP_SERVERS"
            fi
        fi

        if [ "$RUNNING" = "true" ]; then
            RES="Y"
            DESC="시각 동기화가 설정됨"
        else
            RES="N"
            DESC="시각 동기화가 미설정"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check66() {
    local CODE="U-66"
    local CAT="로그관리"
    local NAME="정책에 따른 시스템 로깅 설정"
    local IMP="중"
    local STD="로그 기록 정책이 보안 정책에 따라 설정되어 수립되어 있으며, 로그를 남기고 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset SYSLOG_CONF="/etc/syslog.conf"
        typeset DETAILS=""
        typeset AUTHLOG=""

        if [ -f "$SYSLOG_CONF" ]; then
            # 주요 로그 설정 확인
            AUTHLOG=$(grep -E "auth\.|authpriv\." "$SYSLOG_CONF" 2>/dev/null | head -3)
            typeset MESSAGES=$(grep -E "^\*\.info|^\*\.err|^\*\.notice|^\*\.alert|^\*\.emerg" "$SYSLOG_CONF" 2>/dev/null | head -5)

            DETAILS="syslog.conf 설정:
    $AUTHLOG
    $MESSAGES"
        fi

        # rsyslog.conf 확인 (Solaris 11+에서 rsyslog 사용 가능)
        if [ -f /etc/rsyslog.conf ]; then
            typeset RSYS_AUTH=$(grep -E "auth\.\*|authpriv\.\*" /etc/rsyslog.conf 2>/dev/null | head -3)
            if [ -n "$RSYS_AUTH" ]; then
                DETAILS="${DETAILS}

    rsyslog.conf 설정:
    $RSYS_AUTH"
                if [ -z "$AUTHLOG" ]; then
                    AUTHLOG="$RSYS_AUTH"
                fi
            fi
        fi

        # syslogd 프로세스 확인
        typeset SYSLOGD_RUNNING="false"
        if ps -ef 2>/dev/null | grep -q "[s]yslogd"; then
            SYSLOGD_RUNNING="true"
            DETAILS="${DETAILS}

    syslogd: 실행 중"
        fi

        if [ -n "$AUTHLOG" ]; then
            RES="Y"
            DESC="시스템 로깅이 설정됨"
        elif [ "$SYSLOGD_RUNNING" = "true" ]; then
            RES="M"
            DESC="syslogd 실행 중, 설정 수동 확인 필요"
        else
            RES="N"
            DESC="syslogd 서비스가 실행되지 않음"
            DETAILS="syslogd: 미실행"
        fi

        DT="$DETAILS"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check67() {
    local CODE="U-67"
    local CAT="로그관리"
    local NAME="로그 디렉터리 소유자 및 권한 설정"
    local IMP="중"
    local STD="디렉터리 내 로그 파일의 소유자가 root이고, 권한이 644 이하인 경우"
    local RES=""
    local DESC=""
    local DT=""

        typeset LOG_DIR="/var/log"
        typeset ADM_LOG="/var/adm"
        typeset VULNERABLE=""
        typeset DETAILS=""

        # /var/log 디렉토리 권한 확인
        if [ -d "$LOG_DIR" ]; then
            typeset DIR_PERM=$(get_file_perm "$LOG_DIR")
            typeset DIR_OWNER=$(get_file_owner "$LOG_DIR")
            DETAILS="$LOG_DIR: ${DIR_OWNER}:${DIR_PERM}
    "
        fi

        # /var/adm 디렉토리 권한 확인 (Solaris)
        if [ -d "$ADM_LOG" ]; then
            typeset ADM_PERM=$(get_file_perm "$ADM_LOG")
            typeset ADM_OWNER=$(get_file_owner "$ADM_LOG")
            DETAILS="${DETAILS}$ADM_LOG: ${ADM_OWNER}:${ADM_PERM}
    "
        fi

        # /var/log 주요 로그 파일 권한 확인
        typeset LOG_FILES="syslog messages"
        for log in $LOG_FILES; do
            if [ -f "$LOG_DIR/$log" ]; then
                typeset perm=$(get_file_perm "$LOG_DIR/$log")
                typeset owner=$(get_file_owner "$LOG_DIR/$log")
                DETAILS="${DETAILS}${log}: ${owner}:${perm}
    "
                if [ "$owner" != "root" ] || [ "$perm" -gt 644 ] 2>/dev/null; then
                    VULNERABLE="${VULNERABLE}${log} "
                fi
            fi
        done

        # /var/adm Solaris 주요 로그 파일 권한 확인
        typeset ADM_LOG_FILES="messages wtmpx loginlog sulog"
        for log in $ADM_LOG_FILES; do
            if [ -f "$ADM_LOG/$log" ]; then
                typeset perm=$(get_file_perm "$ADM_LOG/$log")
                typeset owner=$(get_file_owner "$ADM_LOG/$log")
                DETAILS="${DETAILS}${log} (adm): ${owner}:${perm}
    "
                if [ "$owner" != "root" ] || [ "$perm" -gt 644 ] 2>/dev/null; then
                    VULNERABLE="${VULNERABLE}${log} "
                fi
            fi
        done

        if [ -z "$VULNERABLE" ]; then
            RES="Y"
            DESC="로그 파일 권한이 적절히 설정됨"
        else
            RES="N"
            DESC="로그 파일 권한이 부적절함"
        fi

        DT="${DETAILS}취약: ${VULNERABLE:-없음}"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}


#================================================================
# EXECUTE
#================================================================

printf "\n"
printf "  %s Security Assessment v%s [%s]\n" "$META_PLAT" "$META_VER" "$META_STD"
printf "  ─────────────────────────────────────────────────────────\n"
printf "\n"
printf "  호스트: %s\n" "$SYS_HOST"
printf "  OS: %s\n" "$SYS_OS_NAME"
printf "  커널: %s\n" "$SYS_KN"
printf "  IP: %s\n" "$SYS_IP"
printf "\n"
printf "  [진단 시작]\n"
printf "  ─────────────────────────────────────────────────────────\n"
printf "\n"

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
    check27
    check28
    check29
    check30
    check31
    check32
    check33
    check34
    check35
    check36
    check37
    check38
    check39
    check40
    check41
    check42
    check43
    check44
    check45
    check46
    check47
    check48
    check49
    check50
    check51
    check52
    check53
    check54
    check55
    check56
    check57
    check58
    check59
    check60
    check61
    check62
    check63
    check64
    check65
    check66
    check67

# XML 종료
cat >> "$OUTPUT_FILE" << XMLEOF
    </results>
</seedgen>
XMLEOF

#================================================================
# CLEANUP
#================================================================
printf "\n"
printf "  ─────────────────────────────────────────────────────────\n"
printf "\n"
printf "  점검이 완료되었습니다!\n"
printf "  호스트: %s\n" "$SYS_HOST"
printf "  결과 파일: %s\n" "$OUTPUT_FILE"
printf "\n"
