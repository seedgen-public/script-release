#!/bin/bash
#================================================================
# Linux 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : Rocky Linux, Amazon Linux, CentOS, RHEL 등
# 항목  : U-01 ~ U-67 (67개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="Linux"
META_TYPE="Server"

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

    # 콘솔 출력
    case "$RES" in
        "Y")   echo -e "    [[32mY[0m] $CODE $NAME" ;;
        "N")   echo -e "    [[31mN[0m] $CODE $NAME" ;;
        "M")   echo -e "    [[33mM[0m] $CODE $NAME" ;;
        "N/A") echo -e "    [[90m-[0m] $CODE $NAME" ;;
        *)     echo -e "    [-] $CODE $NAME" ;;
    esac

    # XML 출력
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

# 출력 파일 경로
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
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

    # SSH 설정 확인
    local SSHD_CONFIG="/etc/ssh/sshd_config"

    if [ ! -f "$SSHD_CONFIG" ]; then
        RES="N/A"
        DESC="SSH 설정 파일이 존재하지 않아 해당 없음"
        DT="파일: $SSHD_CONFIG (없음)"
    else
        local PERMIT=$(grep -i "^PermitRootLogin" "$SSHD_CONFIG" 2>/dev/null | awk '{print $2}' | head -1)

        if [[ "${PERMIT,,}" == "no" ]]; then
            RES="Y"
            DESC="root 원격 접속이 차단(PermitRootLogin no)되어 양호"
            DT="PermitRootLogin: $PERMIT"
        elif [ -z "$PERMIT" ]; then
            RES="N"
            DESC="PermitRootLogin 설정이 없어 기본값(yes)으로 허용되어 취약"
            DT="PermitRootLogin: not set (default: yes)"
        else
            RES="N"
            DESC="root 원격 접속이 허용(PermitRootLogin $PERMIT)되어 취약"
            DT="PermitRootLogin: $PERMIT"
        fi
    fi

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

    local ISSUES=""
    local DETAILS=""

    # /etc/login.defs 확인
    local PASS_MAX_DAYS=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    local PASS_MIN_DAYS=$(grep "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    DETAILS="PASS_MAX_DAYS: ${PASS_MAX_DAYS:-not set}\nPASS_MIN_DAYS: ${PASS_MIN_DAYS:-not set}"

    # /etc/security/pwquality.conf 확인
    local MINLEN=""
    if [ -f /etc/security/pwquality.conf ]; then
        MINLEN=$(grep "^minlen" /etc/security/pwquality.conf 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
        local DCREDIT=$(grep "^dcredit" /etc/security/pwquality.conf 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
        local UCREDIT=$(grep "^ucredit" /etc/security/pwquality.conf 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
        local LCREDIT=$(grep "^lcredit" /etc/security/pwquality.conf 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
        local OCREDIT=$(grep "^ocredit" /etc/security/pwquality.conf 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
        DETAILS="$DETAILS\nminlen: ${MINLEN:-not set}\ndcredit: ${DCREDIT:-not set}\nucredit: ${UCREDIT:-not set}\nlcredit: ${LCREDIT:-not set}\nocredit: ${OCREDIT:-not set}"
    fi

    # 판단
    local IS_OK=true

    if [ -z "$PASS_MAX_DAYS" ] || [ "$PASS_MAX_DAYS" -gt 90 ] 2>/dev/null; then
        IS_OK=false
        ISSUES="${ISSUES}PASS_MAX_DAYS 미설정 또는 90일 초과, "
    fi

    # [FIX] PASS_MIN_DAYS 미설정 또는 1일 미만 검사 추가 (KISA 조치방법 "최소 사용 기간 1일")
    if [ -z "$PASS_MIN_DAYS" ] || [ "$PASS_MIN_DAYS" -lt 1 ] 2>/dev/null; then
        IS_OK=false
        ISSUES="${ISSUES}PASS_MIN_DAYS 미설정 또는 1일 미만, "
    fi

    if [ -z "$MINLEN" ] || [ "$MINLEN" -lt 8 ] 2>/dev/null; then
        IS_OK=false
        ISSUES="${ISSUES}최소 길이 미설정 또는 8자 미만, "
    fi

    if $IS_OK; then
        RES="Y"
        DESC="비밀번호 관리정책이 기준에 맞게 설정되어 양호"
    else
        RES="N"
        DESC="비밀번호 관리정책이 미흡(${ISSUES%%, })하여 취약"
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

    local DENY_VALUE=""
    local DETAILS=""

    # faillock.conf 확인 (RHEL 8+)
    if [ -f /etc/security/faillock.conf ]; then
        DENY_VALUE=$(grep "^deny" /etc/security/faillock.conf 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ')
        DETAILS="faillock.conf deny: ${DENY_VALUE:-not set}"
    fi

    # PAM 설정 확인
    if [ -z "$DENY_VALUE" ]; then
        DENY_VALUE=$(grep -E "pam_faillock.*deny=" /etc/pam.d/system-auth 2>/dev/null | grep -oP 'deny=\K[0-9]+' | head -1)
        if [ -n "$DENY_VALUE" ]; then
            DETAILS="pam_faillock deny: $DENY_VALUE"
        fi
    fi

    # pam_tally2 확인 (구버전)
    if [ -z "$DENY_VALUE" ]; then
        DENY_VALUE=$(grep -E "pam_tally2.*deny=" /etc/pam.d/system-auth 2>/dev/null | grep -oP 'deny=\K[0-9]+' | head -1)
        if [ -n "$DENY_VALUE" ]; then
            DETAILS="pam_tally2 deny: $DENY_VALUE"
        fi
    fi

    # 판단
    if [ -z "$DENY_VALUE" ]; then
        RES="N"
        DESC="계정 잠금 임계값이 설정되지 않아 취약"
        DT="deny: not set"
    # [FIX] deny=0은 잠금 비활성화이므로 취약 처리 (0<=10 통과 방지)
    elif [ "$DENY_VALUE" -eq 0 ] 2>/dev/null; then
        RES="N"
        DESC="계정 잠금 임계값이 0으로 잠금이 비활성화되어 취약"
        DT="$DETAILS (deny=0은 잠금 비활성화)"
    elif [ "$DENY_VALUE" -le 10 ] 2>/dev/null; then
        RES="Y"
        DESC="계정 잠금 임계값이 10회 이하로 설정되어 양호"
        DT="$DETAILS"
    else
        RES="N"
        DESC="계정 잠금 임계값이 10회를 초과하여 취약"
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

    # /etc/passwd 두 번째 필드 확인
    local UNPROTECTED=$(awk -F: '$2 != "x" && $2 != "" {print $1}' /etc/passwd 2>/dev/null)

    # /etc/shadow 파일 존재 여부
    local SHADOW_EXISTS="N"
    [ -f /etc/shadow ] && SHADOW_EXISTS="Y"

    if [ -z "$UNPROTECTED" ] && [ "$SHADOW_EXISTS" == "Y" ]; then
        RES="Y"
        DESC="/etc/shadow를 통해 비밀번호가 암호화 보호되어 양호"
        DT="/etc/passwd 두 번째 필드: x\n/etc/shadow: 존재함"
    else
        RES="N"
        DESC="비밀번호 파일이 쉐도우 방식으로 보호되지 않아 취약"
        DT="쉐도우 미사용 계정: ${UNPROTECTED:-없음}\n/etc/shadow: $([ "$SHADOW_EXISTS" == "Y" ] && echo '존재함' || echo '없음')"
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
    local UID0_ACCOUNTS=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd 2>/dev/null)

    if [ -z "$UID0_ACCOUNTS" ]; then
        RES="Y"
        DESC="root 외 UID=0 계정이 존재하지 않아 양호"
        DT="UID=0 계정: root만 존재"
    else
        RES="N"
        DESC="root 외 UID=0 계정($UID0_ACCOUNTS)이 존재하여 취약"
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

    local DETAILS=""
    local IS_RESTRICTED=false

    # PAM 모듈 설정 확인
    if grep -q "pam_wheel.so" /etc/pam.d/su 2>/dev/null; then
        local PAM_WHEEL=$(grep "pam_wheel.so" /etc/pam.d/su | grep -v "^#")
        if [ -n "$PAM_WHEEL" ]; then
            IS_RESTRICTED=true
            DETAILS="pam_wheel.so 설정됨\n"
        fi
    fi

    # wheel 그룹 확인
    local WHEEL_GROUP=$(grep "^wheel:" /etc/group 2>/dev/null)
    DETAILS="${DETAILS}wheel 그룹: ${WHEEL_GROUP:-없음}\n"

    # su 권한 확인
    local SU_PERM=$(ls -l /usr/bin/su 2>/dev/null | awk '{print $1, $3, $4}')
    DETAILS="${DETAILS}su 권한: ${SU_PERM:-확인불가}"

    if $IS_RESTRICTED; then
        RES="Y"
        DESC="su 명령어가 pam_wheel.so를 통해 특정 그룹에만 허용되어 양호"
    else
        RES="N"
        DESC="su 명령어가 모든 사용자에게 허용되어 취약"
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

    # 기본 불필요 계정 목록
    local UNNECESSARY="lp uucp nuucp"
    local FOUND_ACCOUNTS=""

    for acc in $UNNECESSARY; do
        if grep -q "^${acc}:" /etc/passwd 2>/dev/null; then
            FOUND_ACCOUNTS="${FOUND_ACCOUNTS}${acc} "
        fi
    done

    # 로그인 가능한 일반 계정 목록
    local LOGIN_ACCOUNTS=$(awk -F: '$3 >= 1000 && $7 !~ /nologin|false/ {print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ')

    if [ -z "$FOUND_ACCOUNTS" ]; then
        RES="M"
        DESC="기본 불필요 계정이 확인되지 않으나 로그인 가능 계정 존재, 수동 확인 필요"
        DT="확인된 불필요 계정: 없음\n로그인 가능 계정: ${LOGIN_ACCOUNTS:-없음}"
    else
        RES="N"
        DESC="불필요한 기본 계정($FOUND_ACCOUNTS)이 존재하여 취약"
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
    local ROOT_GROUP=$(grep "^root:" /etc/group 2>/dev/null)
    local ROOT_MEMBERS=$(echo "$ROOT_GROUP" | cut -d: -f4)

    if [ -z "$ROOT_MEMBERS" ]; then
        RES="Y"
        DESC="관리자 그룹(GID=0)에 불필요한 계정이 없어 양호"
        DT="root 그룹: $ROOT_GROUP"
    else
        RES="M"
        DESC="관리자 그룹(GID=0)에 계정($ROOT_MEMBERS)이 존재, 수동 확인 필요"
        DT="root 그룹: $ROOT_GROUP\n그룹 멤버: $ROOT_MEMBERS"
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

    # 사용 중인 GID 목록 (passwd 파일)
    local USED_GIDS=$(cut -d: -f4 /etc/passwd 2>/dev/null | sort -u)

    # group 파일의 GID 목록
    local ALL_GIDS=$(cut -d: -f3 /etc/group 2>/dev/null | sort -u)

    # 사용되지 않는 그룹 확인 (시스템 그룹 제외)
    local UNUSED_GROUPS=""
    while IFS=: read -r name pass gid members; do
        if [ "$gid" -ge 1000 ] 2>/dev/null; then
            if [ -z "$members" ] && ! echo "$USED_GIDS" | grep -q "^${gid}$"; then
                UNUSED_GROUPS="${UNUSED_GROUPS}${name}(GID:$gid) "
            fi
        fi
    done < /etc/group

    if [ -z "$UNUSED_GROUPS" ]; then
        RES="Y"
        DESC="사용되지 않는 불필요한 그룹이 존재하지 않아 양호"
        DT="사용되지 않는 그룹: 없음"
    else
        RES="M"
        DESC="사용되지 않는 그룹이 존재, 수동 확인 필요"
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
    local DUP_UIDS=$(awk -F: '{print $3}' /etc/passwd 2>/dev/null | sort | uniq -d)

    if [ -z "$DUP_UIDS" ]; then
        RES="Y"
        DESC="동일한 UID를 공유하는 계정이 존재하지 않아 양호"
        DT="중복 UID: 없음"
    else
        local DUP_ACCOUNTS=""
        for uid in $DUP_UIDS; do
            local accounts=$(awk -F: -v uid="$uid" '$3 == uid {print $1}' /etc/passwd | tr '\n' ',' | sed 's/,$//')
            DUP_ACCOUNTS="${DUP_ACCOUNTS}UID=$uid: $accounts\n"
        done
        RES="N"
        DESC="동일한 UID를 공유하는 계정이 존재하여 취약"
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

    # 로그인이 불필요한 계정 목록
    local NOLOGIN_ACCOUNTS="daemon bin sys adm listen nobody nobody4 noaccess diag operator games gopher"
    local VULNERABLE_ACCOUNTS=""

    for acc in $NOLOGIN_ACCOUNTS; do
        local shell=$(grep "^${acc}:" /etc/passwd 2>/dev/null | cut -d: -f7)
        if [ -n "$shell" ] && [[ ! "$shell" =~ (nologin|false) ]]; then
            VULNERABLE_ACCOUNTS="${VULNERABLE_ACCOUNTS}${acc}($shell) "
        fi
    done

    if [ -z "$VULNERABLE_ACCOUNTS" ]; then
        RES="Y"
        DESC="로그인 불필요 계정에 /bin/nologin 또는 /bin/false가 설정되어 양호"
        DT="취약 계정: 없음"
    else
        RES="N"
        DESC="로그인 불필요 계정에 로그인 가능한 쉘이 부여되어 취약"
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

    local TMOUT_VALUE=""
    local DETAILS=""

    # /etc/profile, /etc/bashrc, /etc/profile.d/*.sh 확인
    for profile_file in /etc/profile /etc/bashrc /etc/profile.d/*.sh; do
        if [ -f "$profile_file" ] && [ -z "$TMOUT_VALUE" ]; then
            local found=$(grep -E "^[[:space:]]*(export[[:space:]]+)?TMOUT=" "$profile_file" 2>/dev/null | head -1)
            if [ -n "$found" ]; then
                TMOUT_VALUE=$(echo "$found" | sed 's/.*TMOUT=//' | tr -d ' ')
                DETAILS="$profile_file TMOUT=$TMOUT_VALUE"
            fi
        fi
    done

    # 판단
    if [ -z "$TMOUT_VALUE" ]; then
        RES="N"
        DESC="세션 타임아웃(TMOUT)이 설정되지 않아 취약"
        DT="TMOUT: not set"
    # [FIX] TMOUT=0은 타임아웃 비활성화이므로 취약 처리 (0<=600 통과 방지)
    elif [ "$TMOUT_VALUE" -eq 0 ] 2>/dev/null; then
        RES="N"
        DESC="세션 타임아웃(TMOUT)이 0으로 비활성화되어 취약"
        DT="$DETAILS (TMOUT=0은 타임아웃 비활성화)"
    elif [ "$TMOUT_VALUE" -le 600 ] 2>/dev/null; then
        RES="Y"
        DESC="세션 타임아웃(TMOUT)이 600초 이하로 설정되어 양호"
        DT="$DETAILS (기준: 600초 이하)"
    else
        RES="N"
        DESC="세션 타임아웃(TMOUT)이 600초를 초과하여 취약"
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

    local DETAILS=""
    local HAS_WEAK=false

    # /etc/shadow에서 암호화 알고리즘 확인
    local ENCRYPT_TYPES=$(awk -F: '$2 ~ /^\$/ {print substr($2,1,3)}' /etc/shadow 2>/dev/null | sort | uniq)
    DETAILS="사용 중인 알고리즘: "

    for type in $ENCRYPT_TYPES; do
        case "$type" in
            '$1$') DETAILS="${DETAILS}MD5(취약) "; HAS_WEAK=true ;;
            '$5$') DETAILS="${DETAILS}SHA-256 " ;;
            '$6$') DETAILS="${DETAILS}SHA-512 " ;;
            '$y$') DETAILS="${DETAILS}yescrypt " ;;
            *) DETAILS="${DETAILS}${type} " ;;
        esac
    done

    # /etc/login.defs 확인
    local ENCRYPT_METHOD=$(grep "^ENCRYPT_METHOD" /etc/login.defs 2>/dev/null | awk '{print $2}')
    DETAILS="${DETAILS}\nENCRYPT_METHOD: ${ENCRYPT_METHOD:-not set}"

    if $HAS_WEAK; then
        RES="N"
        DESC="취약한 암호화 알고리즘(MD5)이 사용되고 있어 취약"
    else
        RES="Y"
        DESC="안전한 암호화 알고리즘(SHA-256 이상)이 사용되어 양호"
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
    local ROOT_PATH=$(su - root -c 'echo $PATH' 2>/dev/null)
    local HAS_DOT=false

    # [FIX] 정규식에서 :\.$, ^:.*:$ 패턴 제거 — KISA 기준 "맨 앞이나 중간"만 취약
    if echo "$ROOT_PATH" | grep -qE '^\.|:\.:'; then
        HAS_DOT=true
    fi

    # root 홈 디렉토리 권한 확인
    local ROOT_HOME_PERM=$(stat -c "%a" /root 2>/dev/null)

    if $HAS_DOT; then
        RES="N"
        DESC="root PATH 환경변수에 현재 디렉토리(.)가 포함되어 취약"
        DT="PATH: $ROOT_PATH\nroot 홈 권한: $ROOT_HOME_PERM"
    elif [ "$ROOT_HOME_PERM" -gt 750 ] 2>/dev/null; then
        RES="N"
        DESC="root 홈 디렉토리 권한이 기준(750)을 초과하여 취약"
        DT="root 홈 권한: $ROOT_HOME_PERM (기준: 750 이하)"
    else
        RES="Y"
        DESC="PATH 환경변수에 현재 디렉토리(.)가 없고 root 홈 디렉토리 권한이 기준 이내로 설정되어 양호"
        DT="PATH: $ROOT_PATH\nroot 홈 권한: $ROOT_HOME_PERM"
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

    # 소유자가 없는 파일 확인 (주요 디렉토리만)
    local NOOWNER=$(find /etc /var /tmp -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -10)

    if [ -z "$NOOWNER" ]; then
        RES="Y"
        DESC="소유자가 존재하지 않는 파일 및 디렉토리가 없어 양호"
        DT="소유자 없는 파일: 없음"
    else
        RES="N"
        DESC="소유자가 존재하지 않는 파일 및 디렉토리가 발견되어 취약"
        DT="소유자 없는 파일:\n$NOOWNER"
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

    local TARGET="/etc/passwd"

    if [ ! -f "$TARGET" ]; then
        RES="N/A"
        DESC="/etc/passwd 파일이 존재하지 않아 해당 없음"
        DT="파일: $TARGET (없음)"
    else
        local PERM=$(stat -c "%a" "$TARGET" 2>/dev/null)
        local OWNER=$(stat -c "%U" "$TARGET" 2>/dev/null)

        if [ "$OWNER" == "root" ] && [ "$PERM" -le 644 ] 2>/dev/null; then
            RES="Y"
            DESC="/etc/passwd 파일 소유자가 root이고 권한이 기준(644) 이하로 설정되어 양호"
        else
            RES="N"
            DESC="/etc/passwd 파일 소유자 또는 권한이 기준(root 소유, 644 이하)에 맞지 않아 취약"
        fi
        DT="파일: $TARGET\n소유자: $OWNER\n권한: $PERM"
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

    local VULNERABLE=""
    local TARGETS="/etc/rc.d/init.d /etc/init.d /etc/rc.local"

    for target in $TARGETS; do
        if [ -e "$target" ]; then
            # 심볼릭 링크인 경우 실제 파일 경로 확인
            local real_target="$target"
            if [ -L "$target" ]; then
                real_target=$(readlink -f "$target" 2>/dev/null)
                [ -z "$real_target" ] && continue
            fi

            local perm=$(stat -c "%a" "$real_target" 2>/dev/null)
            local owner=$(stat -c "%U" "$real_target" 2>/dev/null)
            # [FIX] group 쓰기 권한도 검사 추가 (KISA "일반 사용자의 쓰기 권한" = group + other)
            local group_perm=$(( (perm / 10) % 10 ))
            local other_perm=$((perm % 10))
            if [ "$owner" != "root" ] || [ $((group_perm & 2)) -ne 0 ] || [ $((other_perm & 2)) -ne 0 ] 2>/dev/null; then
                VULNERABLE="${VULNERABLE}${target}(${owner}:${perm}) "
            fi

            # [FIX] 디렉토리인 경우 내부 개별 스크립트 파일도 순회 점검
            if [ -d "$real_target" ]; then
                for script_file in "$real_target"/*; do
                    [ -f "$script_file" ] || continue
                    local s_perm=$(stat -c "%a" "$script_file" 2>/dev/null)
                    local s_owner=$(stat -c "%U" "$script_file" 2>/dev/null)
                    local s_group_perm=$(( (s_perm / 10) % 10 ))
                    local s_other_perm=$((s_perm % 10))
                    if [ "$s_owner" != "root" ] || [ $((s_group_perm & 2)) -ne 0 ] || [ $((s_other_perm & 2)) -ne 0 ]; then
                        VULNERABLE="${VULNERABLE}${script_file}(${s_owner}:${s_perm}) "
                    fi
                done
            fi
        fi
    done

    # 검사 대상 목록 생성
    local CHECKED_LIST=""
    for target in $TARGETS; do
        if [ -e "$target" ]; then
            local real_target="$target"
            if [ -L "$target" ]; then
                real_target=$(readlink -f "$target" 2>/dev/null)
                [ -z "$real_target" ] && continue
            fi
            local perm=$(stat -c "%a" "$real_target" 2>/dev/null)
            local owner=$(stat -c "%U" "$real_target" 2>/dev/null)
            CHECKED_LIST="${CHECKED_LIST}  - ${target} (${owner}:${perm})\n"
        fi
    done

    if [ -z "$VULNERABLE" ]; then
        RES="Y"
        DESC="시스템 시작 스크립트의 소유자 및 권한이 기준에 맞게 설정되어 양호"
        DT="[검사 대상]\n${CHECKED_LIST}\n[취약 파일]\n없음"
    else
        RES="N"
        DESC="시스템 시작 스크립트의 소유자 또는 권한이 기준에 맞지 않아 취약"
        DT="[검사 대상]\n${CHECKED_LIST}\n[취약 파일]\n$VULNERABLE"
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

    local TARGET="/etc/shadow"

    if [ ! -f "$TARGET" ]; then
        RES="N/A"
        DESC="/etc/shadow 파일이 존재하지 않아 해당 없음"
        DT="파일: $TARGET (없음)"
    else
        local PERM=$(stat -c "%a" "$TARGET" 2>/dev/null)
        local OWNER=$(stat -c "%U" "$TARGET" 2>/dev/null)

        if [ "$OWNER" == "root" ] && [ "$PERM" -le 400 ] 2>/dev/null; then
            RES="Y"
            DESC="/etc/shadow 파일 소유자가 root이고 권한이 기준(400) 이하로 설정되어 양호"
        else
            RES="N"
            DESC="/etc/shadow 파일 소유자 또는 권한이 기준(root 소유, 400 이하)에 맞지 않아 취약"
        fi
        DT="파일: $TARGET\n소유자: $OWNER\n권한: $PERM (기준: 400 이하)"
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

    local TARGET="/etc/hosts"

    if [ ! -f "$TARGET" ]; then
        RES="N/A"
        DESC="/etc/hosts 파일이 존재하지 않아 해당 없음"
        DT="파일: $TARGET (없음)"
    else
        local PERM=$(stat -c "%a" "$TARGET" 2>/dev/null)
        local OWNER=$(stat -c "%U" "$TARGET" 2>/dev/null)

        if [ "$OWNER" == "root" ] && [ "$PERM" -le 644 ] 2>/dev/null; then
            RES="Y"
            DESC="/etc/hosts 파일 소유자가 root이고 권한이 기준(644) 이하로 설정되어 양호"
        else
            RES="N"
            DESC="/etc/hosts 파일 소유자 또는 권한이 기준(root 소유, 644 이하)에 맞지 않아 취약"
        fi
        DT="파일: $TARGET\n소유자: $OWNER\n권한: $PERM"
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

    local TARGETS="/etc/inetd.conf /etc/xinetd.conf"
    local FOUND=false
    local VULNERABLE=""
    local DETAILS=""

    for target in $TARGETS; do
        if [ -f "$target" ]; then
            FOUND=true
            local perm=$(stat -c "%a" "$target" 2>/dev/null)
            local owner=$(stat -c "%U" "$target" 2>/dev/null)
            DETAILS="${DETAILS}${target}: ${owner}:${perm}\n"
            if [ "$owner" != "root" ] || [ "$perm" -gt 600 ] 2>/dev/null; then
                VULNERABLE="${VULNERABLE}${target} "
            fi
        fi
    done

    if ! $FOUND; then
        RES="N/A"
        DESC="inetd/xinetd 설정 파일이 존재하지 않아 해당 없음"
        DT="(x)inetd.conf: 미사용"
    elif [ -z "$VULNERABLE" ]; then
        RES="Y"
        DESC="(x)inetd.conf 파일 소유자가 root이고 권한이 기준(600) 이하로 설정되어 양호"
        DT="$DETAILS"
    else
        RES="N"
        DESC="(x)inetd.conf 파일 소유자 또는 권한이 기준(root 소유, 600 이하)에 맞지 않아 취약"
        DT="$DETAILS취약 파일: $VULNERABLE"
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

    local TARGETS="/etc/rsyslog.conf /etc/syslog.conf"
    local FOUND=false
    local VULNERABLE=""
    local DETAILS=""

    for target in $TARGETS; do
        if [ -f "$target" ]; then
            FOUND=true
            local perm=$(stat -c "%a" "$target" 2>/dev/null)
            local owner=$(stat -c "%U" "$target" 2>/dev/null)
            DETAILS="${DETAILS}${target}: ${owner}:${perm}\n"
            # [FIX] bin, sys 소유자도 허용 (KISA "소유자가 root 또는 bin, sys")
            if [ "$owner" != "root" ] && [ "$owner" != "bin" ] && [ "$owner" != "sys" ] || [ "$perm" -gt 640 ] 2>/dev/null; then
                VULNERABLE="${VULNERABLE}${target} "
            fi
        fi
    done

    if ! $FOUND; then
        RES="N/A"
        DESC="syslog 설정 파일이 존재하지 않아 해당 없음"
        DT="(r)syslog.conf: 없음"
    elif [ -z "$VULNERABLE" ]; then
        RES="Y"
        DESC="syslog 설정 파일 소유자 및 권한이 기준(root/bin/sys 소유, 640 이하)에 맞게 설정되어 양호"
        DT="$DETAILS"
    else
        RES="N"
        DESC="syslog 설정 파일 소유자 또는 권한이 기준(root/bin/sys 소유, 640 이하)에 맞지 않아 취약"
        DT="$DETAILS취약 파일: $VULNERABLE"
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

    local TARGET="/etc/services"

    if [ ! -f "$TARGET" ]; then
        RES="N/A"
        DESC="/etc/services 파일이 존재하지 않아 해당 없음"
        DT="파일: $TARGET (없음)"
    else
        local PERM=$(stat -c "%a" "$TARGET" 2>/dev/null)
        local OWNER=$(stat -c "%U" "$TARGET" 2>/dev/null)

        # [FIX] KISA 기준 "소유자가 root(또는 bin, sys)" — bin, sys 소유자 허용 추가
        if { [ "$OWNER" == "root" ] || [ "$OWNER" == "bin" ] || [ "$OWNER" == "sys" ]; } && [ "$PERM" -le 644 ] 2>/dev/null; then
            RES="Y"
            DESC="/etc/services 파일 소유자 및 권한이 기준(root/bin/sys 소유, 644 이하)에 맞게 설정되어 양호"
        else
            RES="N"
            DESC="/etc/services 파일 소유자 또는 권한이 기준(root/bin/sys 소유, 644 이하)에 맞지 않아 취약"
        fi
        DT="파일: $TARGET\n소유자: $OWNER\n권한: $PERM"
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
    local SUID_FILES=$(find /usr /bin /sbin -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -20)
    local COUNT=$(echo "$SUID_FILES" | grep -c .)

    RES="M"
    DESC="SUID/SGID 설정 파일 ${COUNT}개 발견, 수동 확인 필요"
    DT="SUID/SGID 파일 목록:\n$SUID_FILES\n...(상위 20개만 표시)"

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

    local TARGETS="/etc/profile /etc/bashrc /root/.bashrc /root/.bash_profile"
    local VULNERABLE=""
    local DETAILS=""

    for target in $TARGETS; do
        if [ -f "$target" ]; then
            local perm=$(stat -c "%a" "$target" 2>/dev/null)
            local owner=$(stat -c "%U" "$target" 2>/dev/null)
            DETAILS="${DETAILS}${target}: ${owner}:${perm}\n"
            if [ "$owner" != "root" ] || [ "$perm" -gt 644 ] 2>/dev/null; then
                VULNERABLE="${VULNERABLE}${target} "
            fi
        fi
    done

    # [FIX] UID>=1000 일반 사용자 홈 디렉토리 환경변수 파일 점검 추가
    local ENV_FILES=".profile .bashrc .bash_profile .kshrc .cshrc .login"
    while IFS=: read -r uname _ uid _ _ homedir _; do
        # nfsnobody, nobody 제외, UID >= 1000 일반 사용자만 대상
        [ "$uid" -ge 1000 ] 2>/dev/null || continue
        [ "$uname" == "nfsnobody" ] && continue
        [ "$uname" == "nobody" ] && continue
        [ -d "$homedir" ] || continue

        for ef in $ENV_FILES; do
            local efile="${homedir}/${ef}"
            [ -f "$efile" ] || continue
            local eperm=$(stat -c "%a" "$efile" 2>/dev/null)
            local eowner=$(stat -c "%U" "$efile" 2>/dev/null)
            DETAILS="${DETAILS}${efile}: ${eowner}:${eperm}\n"
            # [FIX] 소유자가 해당 사용자 또는 root이고, 권한이 644 이하(group/other 쓰기 없음)면 양호
            if { [ "$eowner" != "$uname" ] && [ "$eowner" != "root" ]; } || [ "$eperm" -gt 644 ] 2>/dev/null; then
                VULNERABLE="${VULNERABLE}${efile} "
            fi
        done
    done < /etc/passwd

    if [ -z "$VULNERABLE" ]; then
        RES="Y"
        DESC="환경변수 파일 소유자 및 권한(644 이하)이 기준에 맞게 설정되어 양호"
        DT="$DETAILS"
    else
        RES="N"
        DESC="환경변수 파일 소유자 또는 권한이 기준(644)을 초과하여 취약"
        DT="$DETAILS취약 파일: $VULNERABLE"
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

    # [FIX] 검사 범위를 / 전체로 확장 (로컬 파일시스템만)
    local SEARCH_DIRS="/"

    # [FIX] -xdev 추가, /proc /sys /dev prune, 심볼릭 링크 제외
    local WW_FILES=$(find / -xdev \( -path /proc -o -path /sys -o -path /dev \) -prune -o -type f -perm -0002 ! -type l -print 2>/dev/null | head -20)
    local WW_COUNT=$(echo "$WW_FILES" | grep -c . 2>/dev/null)
    [ -z "$WW_FILES" ] && WW_COUNT=0

    if [ "$WW_COUNT" -eq 0 ]; then
        RES="Y"
        DESC="world writable 파일이 존재하지 않아 양호"
        DT="[검사 범위]\n  로컬 파일시스템 전체 (-xdev)\n  제외: /proc, /sys, /dev\n\n[world writable 파일]\n없음"
    else
        # [FIX] N → M 변경: KISA "관리자 인지 시 양호"이므로 자동 Y/N 불가
        RES="M"
        DESC="world writable 파일 ${WW_COUNT}개 존재, 수동 확인 필요"
        DT="[검사 범위]\n  로컬 파일시스템 전체 (-xdev)\n  제외: /proc, /sys, /dev\n\n[world writable 파일] (최대 20개 표시)\n$WW_FILES"
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
    local EXCLUDE_PATHS="/dev, /proc, /sys, /run, /selinux"

    # /dev 외부의 device 파일 검색 (가상 파일시스템 제외)
    local DEV_FILES=$(find / \
        -path /dev -prune -o \
        -path /proc -prune -o \
        -path /sys -prune -o \
        -path /run -prune -o \
        -path /selinux -prune -o \
        \( -type b -o -type c \) -print 2>/dev/null | head -10)
    local DEV_COUNT=$(find / \
        -path /dev -prune -o \
        -path /proc -prune -o \
        -path /sys -prune -o \
        -path /run -prune -o \
        -path /selinux -prune -o \
        \( -type b -o -type c \) -print 2>/dev/null | wc -l)

    if [ -z "$DEV_FILES" ]; then
        RES="Y"
        DESC="/dev 외부에 device 파일이 존재하지 않아 양호"
        DT="[검사 범위]\n  전체 파일시스템 (/ 기준)\n\n[제외 경로]\n  $EXCLUDE_PATHS\n\n[비정상 device 파일]\n없음"
    else
        RES="N"
        DESC="/dev 외부에 device 파일이 ${DEV_COUNT}개 존재하여 취약"
        DT="[검사 범위]\n  전체 파일시스템 (/ 기준)\n\n[제외 경로]\n  $EXCLUDE_PATHS\n\n[비정상 device 파일] (최대 10개 표시)\n$DEV_FILES"
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

    local VULNERABLE=""
    local DETAILS=""

    # /etc/hosts.equiv 확인
    if [ -f /etc/hosts.equiv ]; then
        VULNERABLE="${VULNERABLE}/etc/hosts.equiv "
        DETAILS="${DETAILS}/etc/hosts.equiv: 존재\n"
    fi

    # 사용자 홈 디렉토리의 .rhosts 확인
    while IFS=: read -r user _ _ _ _ home _; do
        if [ -f "${home}/.rhosts" ] 2>/dev/null; then
            VULNERABLE="${VULNERABLE}${home}/.rhosts "
            DETAILS="${DETAILS}${home}/.rhosts: 존재\n"
        fi
    done < /etc/passwd

    if [ -z "$VULNERABLE" ]; then
        RES="Y"
        DESC=".rhosts, hosts.equiv 파일이 존재하지 않아 양호"
        DT="취약 파일: 없음"
    else
        RES="N"
        DESC=".rhosts, hosts.equiv 파일이 존재하여 취약"
        DT="$DETAILS"
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

    local DETAILS=""
    local HAS_RESTRICTION=false

    # hosts.allow / hosts.deny 확인
    if [ -f /etc/hosts.allow ]; then
        local ALLOW_CONTENT=$(grep -v "^#" /etc/hosts.allow | grep -v "^$" | head -5)
        if [ -n "$ALLOW_CONTENT" ]; then
            DETAILS="${DETAILS}hosts.allow:\n$ALLOW_CONTENT\n"
            HAS_RESTRICTION=true
        fi
    fi

    if [ -f /etc/hosts.deny ]; then
        local DENY_CONTENT=$(grep -v "^#" /etc/hosts.deny | grep -v "^$" | head -5)
        if [ -n "$DENY_CONTENT" ]; then
            DETAILS="${DETAILS}hosts.deny:\n$DENY_CONTENT\n"
            HAS_RESTRICTION=true
        fi
    fi

    # iptables/firewalld 확인
    if command -v firewall-cmd &>/dev/null; then
        local FW_STATUS=$(firewall-cmd --state 2>/dev/null)
        DETAILS="${DETAILS}firewalld: $FW_STATUS\n"
        [ "$FW_STATUS" == "running" ] && HAS_RESTRICTION=true
    fi

    # [FIX] iptables 규칙 확인 추가
    if command -v iptables &>/dev/null; then
        local IPT_RULES=$(iptables -L -n 2>/dev/null | grep -cv "^Chain\|^target\|^$")
        if [ "$IPT_RULES" -gt 0 ] 2>/dev/null; then
            DETAILS="${DETAILS}iptables: ${IPT_RULES}개 규칙\n"
            HAS_RESTRICTION=true
        fi
    fi

    # [FIX] nftables 규칙 확인 추가
    if command -v nft &>/dev/null; then
        local NFT_RULES=$(nft list ruleset 2>/dev/null | grep -c "rule")
        if [ "$NFT_RULES" -gt 0 ] 2>/dev/null; then
            DETAILS="${DETAILS}nftables: ${NFT_RULES}개 규칙\n"
            HAS_RESTRICTION=true
        fi
    fi

    if $HAS_RESTRICTION; then
        RES="Y"
        DESC="접속 IP 및 포트 제한이 설정되어 양호"
    else
        RES="N"
        DESC="접속 IP 및 포트 제한이 설정되지 않아 취약"
        # [FIX] N 판정 시에도 확인 결과 표시
        [ -z "$DETAILS" ] && DETAILS="hosts.allow: 설정 없음\nhosts.deny: 설정 없음\nfirewalld/iptables/nftables: 미사용"
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

    local TARGET="/etc/hosts.lpd"

    if [ ! -f "$TARGET" ]; then
        RES="N/A"
        DESC="/etc/hosts.lpd 파일이 존재하지 않아 해당 없음"
        DT="파일: $TARGET (없음)"
    else
        local PERM=$(stat -c "%a" "$TARGET" 2>/dev/null)
        local OWNER=$(stat -c "%U" "$TARGET" 2>/dev/null)

        if [ "$OWNER" == "root" ] && [ "$PERM" -le 600 ] 2>/dev/null; then
            RES="Y"
            DESC="/etc/hosts.lpd 파일 소유자가 root이고 권한이 600 이하로 설정되어 양호"
        else
            RES="N"
            DESC="/etc/hosts.lpd 파일 소유자 또는 권한이 기준(600)을 초과하여 취약"
        fi
        DT="파일: $TARGET\n소유자: $OWNER\n권한: $PERM"
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

    local UMASK_VALUE=""
    local DETAILS=""

    # /etc/profile 확인
    UMASK_VALUE=$(grep -i "^umask" /etc/profile 2>/dev/null | awk '{print $2}' | head -1)
    if [ -n "$UMASK_VALUE" ]; then
        DETAILS="/etc/profile UMASK=$UMASK_VALUE"
    fi

    # /etc/bashrc 확인
    if [ -z "$UMASK_VALUE" ]; then
        UMASK_VALUE=$(grep -i "^umask" /etc/bashrc 2>/dev/null | awk '{print $2}' | head -1)
        if [ -n "$UMASK_VALUE" ]; then
            DETAILS="/etc/bashrc UMASK=$UMASK_VALUE"
        fi
    fi

    # 현재 umask
    local CURRENT_UMASK=$(umask)
    DETAILS="${DETAILS}\n현재 UMASK: $CURRENT_UMASK"

    # 판단 (022 또는 027 권장)
    if [ "$UMASK_VALUE" == "022" ] || [ "$UMASK_VALUE" == "027" ] || [ "$CURRENT_UMASK" == "0022" ] || [ "$CURRENT_UMASK" == "0027" ]; then
        RES="Y"
        DESC="UMASK 값이 022 이상으로 설정되어 양호"
    else
        RES="N"
        DESC="UMASK 값이 022 미만으로 설정되어 취약"
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

    local VULNERABLE=""
    local DETAILS=""

    while IFS=: read -r user _ uid _ _ home _; do
        if [ "$uid" -ge 1000 ] 2>/dev/null && [ -d "$home" ]; then
            local perm=$(stat -c "%a" "$home" 2>/dev/null)
            local owner=$(stat -c "%U" "$home" 2>/dev/null)
            # other 쓰기 권한(2) 여부 확인 (가이드라인: 타 사용자 쓰기 권한 제거)
            local other_perm=$((perm % 10))
            if [ "$owner" != "$user" ] || [ $((other_perm & 2)) -ne 0 ] 2>/dev/null; then
                VULNERABLE="${VULNERABLE}${home}(${owner}:${perm}) "
            fi
            DETAILS="${DETAILS}${user}: ${home}(${owner}:${perm})\n"
        fi
    done < /etc/passwd

    if [ -z "$VULNERABLE" ]; then
        RES="Y"
        DESC="홈 디렉토리 소유자 및 권한이 기준에 맞게 설정되어 양호"
    else
        RES="N"
        DESC="홈 디렉토리 소유자 또는 권한(other 쓰기)이 기준을 초과하여 취약"
    fi
    DT="$DETAILS취약: ${VULNERABLE:-없음}"

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

    local MISSING=""
    local DETAILS=""

    while IFS=: read -r user _ uid _ _ home _; do
        if [ "$uid" -ge 1000 ] 2>/dev/null; then
            if [ ! -d "$home" ]; then
                MISSING="${MISSING}${user}:${home} "
            fi
        fi
    done < /etc/passwd

    if [ -z "$MISSING" ]; then
        RES="Y"
        DESC="모든 사용자의 홈 디렉토리가 존재하여 양호"
        DT="누락된 홈 디렉토리: 없음"
    else
        RES="N"
        DESC="존재하지 않는 홈 디렉토리가 있어 취약"
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
    local HIDDEN_FILES=$(find /home /root -name ".*" -type f 2>/dev/null | head -20)
    local COUNT=$(echo "$HIDDEN_FILES" | grep -c .)

    RES="M"
    DESC="홈 디렉토리 내 숨김 파일 ${COUNT}개 발견, 수동 확인 필요"
    DT="숨김 파일 목록:\n$HIDDEN_FILES\n...(상위 20개만 표시)"

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

    local RUNNING=false
    local DETAILS=""

    # 프로세스 확인
    if pgrep -x "fingerd" &>/dev/null; then
        RUNNING=true
        DETAILS="fingerd 프로세스: 실행 중\n"
    fi

    # 포트 확인
    if ss -tuln 2>/dev/null | grep -q ":79 "; then
        RUNNING=true
        DETAILS="${DETAILS}포트 79: 사용 중\n"
    fi

    if $RUNNING; then
        RES="N"
        DESC="Finger 서비스(fingerd)가 실행 중이어서 취약"
    else
        RES="Y"
        DESC="Finger 서비스(fingerd)가 비활성화되어 양호"
        DETAILS="fingerd: 미실행"
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

    local VULNERABLE=false
    local DETAILS=""

    # NFS exports 확인
    if [ -f /etc/exports ]; then
        local EXPORTS=$(cat /etc/exports | grep -v "^#" | grep -v "^$")
        if [ -n "$EXPORTS" ]; then
            DETAILS="NFS exports:\n$EXPORTS\n"
            if echo "$EXPORTS" | grep -q "no_root_squash\|insecure\|\*"; then
                VULNERABLE=true
            fi
        fi
    fi

    # Samba 확인
    if [ -f /etc/samba/smb.conf ]; then
        local GUEST=$(grep -i "guest ok\|public" /etc/samba/smb.conf | grep -i "yes")
        if [ -n "$GUEST" ]; then
            VULNERABLE=true
            DETAILS="${DETAILS}Samba guest 허용 설정 발견\n"
        fi
    fi

    if $VULNERABLE; then
        RES="N"
        DESC="NFS/Samba 익명 접근이 허용되어 취약"
    else
        RES="Y"
        DESC="NFS/Samba 익명 접근이 제한되어 양호"
    fi

    DT="${DETAILS:-공유 서비스 설정: 양호}"

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

    local RUNNING=""
    local DETAILS=""

    # 프로세스 확인
    for svc in rlogind rshd rexecd; do
        if pgrep -x "$svc" &>/dev/null; then
            RUNNING="${RUNNING}${svc} "
        fi
    done

    # [FIX] 포트 확인 결과를 판정에 반영 — 포트 열려있으면 RUNNING에 추가
    if ss -tuln 2>/dev/null | grep -qE ":512 |:513 |:514 "; then
        DETAILS="r 계열 포트 사용 중"
        [ -z "$RUNNING" ] && RUNNING="port(512/513/514) "
    fi

    if [ -n "$RUNNING" ]; then
        RES="N"
        DESC="r 계열 서비스(rlogin/rsh/rexec)가 실행 중이어서 취약"
        DT="실행 중: $RUNNING\n$DETAILS"
    else
        RES="Y"
        DESC="r 계열 서비스(rlogin/rsh/rexec)가 비활성화되어 양호"
        DT="r 계열 서비스: 미실행"
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

    local VULNERABLE=""
    local DETAILS=""

    # crontab 관련 파일/디렉토리 확인
    local TARGETS="/etc/crontab /etc/cron.allow /etc/cron.deny /var/spool/cron"

    for target in $TARGETS; do
        if [ -e "$target" ]; then
            local perm=$(stat -c "%a" "$target" 2>/dev/null)
            local owner=$(stat -c "%U" "$target" 2>/dev/null)
            DETAILS="${DETAILS}${target}: ${owner}:${perm}\n"
            if [ "$owner" != "root" ]; then
                VULNERABLE="${VULNERABLE}${target} "
            fi
        fi
    done

    if [ -z "$VULNERABLE" ]; then
        RES="Y"
        DESC="crontab 관련 파일 소유자가 root로 설정되어 양호"
    else
        RES="N"
        DESC="crontab 관련 파일 소유자가 root가 아니어서 취약"
    fi

    DT="$DETAILS취약: ${VULNERABLE:-없음}"

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

    local VULNERABLE_SVCS="echo discard daytime chargen"
    local RUNNING=""
    local DETAILS=""

    # [FIX] xinetd.d 개별 파일에서 disable 여부 확인 방식으로 변경
    for svc in $VULNERABLE_SVCS; do
        # xinetd.d 설정 확인
        for conf in /etc/xinetd.d/*; do
            [ -f "$conf" ] || continue
            if grep -q "service.*$svc" "$conf" 2>/dev/null; then
                if ! grep -q "disable.*=.*yes" "$conf" 2>/dev/null; then
                    RUNNING="${RUNNING}${svc}(xinetd) "
                fi
            fi
        done
        # [FIX] systemd 환경 확인 추가
        if systemctl is-active "${svc}.socket" &>/dev/null || systemctl is-active "${svc}@.service" &>/dev/null; then
            RUNNING="${RUNNING}${svc}(systemd) "
        fi
    done

    if [ -z "$RUNNING" ]; then
        RES="Y"
        DESC="DoS 취약 서비스(echo/discard/daytime/chargen)가 비활성화되어 양호"
        DT="echo, discard, daytime, chargen: 비활성"
    else
        RES="N"
        DESC="DoS 취약 서비스(echo/discard/daytime/chargen)가 활성화되어 취약"
        DT="활성화된 서비스: $RUNNING"
    fi

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

    local RUNNING=false
    local DETAILS=""

    # NFS 서비스 확인
    if systemctl is-active nfs-server &>/dev/null || systemctl is-active nfs &>/dev/null; then
        RUNNING=true
        DETAILS="NFS 서비스: 실행 중\n"
    fi

    # rpcbind 확인
    if systemctl is-active rpcbind &>/dev/null; then
        DETAILS="${DETAILS}rpcbind: 실행 중\n"
    fi

    # 포트 확인
    if ss -tuln 2>/dev/null | grep -q ":2049 "; then
        RUNNING=true
        DETAILS="${DETAILS}포트 2049: 사용 중\n"
    fi

    if $RUNNING; then
        RES="M"
        DESC="NFS 서비스가 실행 중, 수동 확인 필요"
    else
        RES="Y"
        DESC="NFS 서비스가 비활성화되어 양호"
        DETAILS="NFS: 미실행"
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

    if [ ! -f /etc/exports ]; then
        RES="N/A"
        DESC="NFS exports 파일이 존재하지 않아 해당 없음"
        DT="/etc/exports: 없음"
    else
        local EXPORTS=$(cat /etc/exports | grep -v "^#" | grep -v "^$")
        if [ -z "$EXPORTS" ]; then
            RES="Y"
            DESC="NFS 공유 설정이 비어 있어 양호"
            DT="/etc/exports: 비어있음"
        elif echo "$EXPORTS" | grep -q "\*"; then
            RES="N"
            DESC="NFS 접근 통제에 와일드카드(*)가 사용되어 취약"
            DT="/etc/exports:\n$EXPORTS"
        else
            RES="M"
            DESC="NFS 접근 통제 설정 확인, 수동 확인 필요"
            DT="/etc/exports:\n$EXPORTS"
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

    local RUNNING=false
    local DETAILS=""

    # autofs 서비스 확인
    if systemctl is-active autofs &>/dev/null; then
        RUNNING=true
        DETAILS="autofs: 실행 중"
    fi

    # automount 프로세스 확인
    if pgrep -x "automount" &>/dev/null; then
        RUNNING=true
        DETAILS="${DETAILS}\nautomount 프로세스: 실행 중"
    fi

    if $RUNNING; then
        RES="N"
        DESC="automountd 서비스가 실행 중이어서 취약"
    else
        RES="Y"
        DESC="automountd 서비스가 비활성화되어 양호"
        DETAILS="automount: 미실행"
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

    local RPC_SVCS="rpc.cmsd rpc.ttdbserverd sadmind rusersd walld sprayd rstatd rpc.nisd rexd rpc.pcnfsd rpc.statd rpc.ypupdated rpc.rquotad kcms_server cachefsd"
    local RUNNING=""

    for svc in $RPC_SVCS; do
        if pgrep -x "$svc" &>/dev/null; then
            RUNNING="${RUNNING}${svc} "
        fi
    done

    # rpcbind 상태 확인
    local RPCBIND_STATUS=""
    if systemctl is-active rpcbind &>/dev/null; then
        RPCBIND_STATUS="rpcbind: 실행 중"
    else
        RPCBIND_STATUS="rpcbind: 미실행"
    fi

    if [ -z "$RUNNING" ]; then
        RES="Y"
        DESC="불필요한 RPC 서비스가 비활성화되어 양호"
        DT="$RPCBIND_STATUS\n취약 RPC 서비스: 미실행"
    else
        RES="N"
        DESC="불필요한 RPC 서비스가 실행 중이어서 취약"
        DT="$RPCBIND_STATUS\n실행 중: $RUNNING"
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

    local RUNNING=false
    local DETAILS=""

    # NIS 서비스 확인
    for svc in ypserv ypbind yppasswdd ypxfrd; do
        if pgrep -x "$svc" &>/dev/null; then
            RUNNING=true
            DETAILS="${DETAILS}${svc}: 실행 중\n"
        fi
    done

    # systemd 서비스 확인
    if systemctl is-active ypbind &>/dev/null; then
        RUNNING=true
        DETAILS="${DETAILS}ypbind.service: 실행 중\n"
    fi

    if $RUNNING; then
        RES="N"
        DESC="NIS/NIS+ 서비스가 실행 중이어서 취약"
    else
        RES="Y"
        DESC="NIS/NIS+ 서비스가 비활성화되어 양호"
        DETAILS="NIS 서비스: 미실행"
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

    local RUNNING=""
    local DETAILS=""

    # tftp 확인
    # [FIX] pgrep -x에서 | 패턴 미지원 → 개별 호출로 분리
    if pgrep -x "in.tftpd" &>/dev/null || pgrep -x "tftpd" &>/dev/null || ss -tuln | grep -q ":69 "; then
        RUNNING="${RUNNING}tftp "
    fi

    # talk 확인
    # [FIX] pgrep -x에서 | 패턴 미지원 → 개별 호출로 분리
    if pgrep -x "in.talkd" &>/dev/null || pgrep -x "talkd" &>/dev/null || pgrep -x "in.ntalkd" &>/dev/null || pgrep -x "ntalkd" &>/dev/null || ss -tuln | grep -q ":517 \|:518 "; then
        RUNNING="${RUNNING}talk "
    fi

    if [ -z "$RUNNING" ]; then
        RES="Y"
        DESC="tftp, talk 서비스가 비활성화되어 양호"
        DT="tftp, talk: 미실행"
    else
        RES="N"
        DESC="tftp 또는 talk 서비스가 실행 중이어서 취약"
        DT="실행 중: $RUNNING"
    fi

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

    local DETAILS=""

    # sendmail 버전 확인
    if command -v sendmail &>/dev/null; then
        local SENDMAIL_VER=$(sendmail -d0.1 -bv root 2>&1 | head -1)
        DETAILS="sendmail: $SENDMAIL_VER"
        RES="M"
        DESC="메일 서비스 설치 확인, 수동 확인 필요"
    # postfix 버전 확인
    elif command -v postfix &>/dev/null; then
        local POSTFIX_VER=$(postconf -d mail_version 2>/dev/null | cut -d'=' -f2)
        DETAILS="postfix: $POSTFIX_VER"
        RES="M"
        DESC="메일 서비스 설치 확인, 수동 확인 필요"
    else
        RES="N/A"
        DESC="메일 서비스(sendmail/postfix)가 미설치되어 해당 없음"
        DETAILS="sendmail/postfix: 미설치"
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

    local SENDMAIL_PATH=$(which sendmail 2>/dev/null)

    if [ -z "$SENDMAIL_PATH" ]; then
        RES="N/A"
        DESC="sendmail이 미설치되어 해당 없음"
        DT="sendmail: 미설치"
    else
        local PERM=$(stat -c "%a" "$SENDMAIL_PATH" 2>/dev/null)
        local DETAILS="$SENDMAIL_PATH: $PERM"
        local HAS_ISSUE=false

        # SUID 비트 확인
        if [ $((PERM & 4000)) -ne 0 ]; then
            HAS_ISSUE=true
            DETAILS="${DETAILS}\nSUID 비트: 설정됨 (취약)"
        else
            DETAILS="${DETAILS}\nSUID 비트: 미설정 (양호)"
        fi

        # sendmail.cf PrivacyOptions 확인
        local SENDMAIL_CF="/etc/mail/sendmail.cf"
        if [ -f "$SENDMAIL_CF" ]; then
            local PRIVACY=$(grep -i "^O PrivacyOptions" "$SENDMAIL_CF" 2>/dev/null)
            if echo "$PRIVACY" | grep -qi "restrictqrun"; then
                DETAILS="${DETAILS}\nPrivacyOptions: restrictqrun 설정됨 (양호)"
            else
                HAS_ISSUE=true
                DETAILS="${DETAILS}\nPrivacyOptions: restrictqrun 미설정 (취약)"
            fi
        fi

        if $HAS_ISSUE; then
            RES="N"
            DESC="sendmail SUID 비트 또는 PrivacyOptions 설정이 미흡하여 취약"
        else
            RES="Y"
            DESC="sendmail SUID 비트 미설정 및 PrivacyOptions가 적절히 설정되어 양호"
        fi
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

    local DETAILS=""

    # sendmail.cf 확인
    if [ -f /etc/mail/sendmail.cf ]; then
        local RELAY=$(grep -i "R$\*" /etc/mail/sendmail.cf | head -3)
        DETAILS="sendmail.cf 릴레이 설정:\n$RELAY"
        RES="M"
        DESC="메일 릴레이 설정 확인, 수동 확인 필요"
    # postfix 확인
    elif [ -f /etc/postfix/main.cf ]; then
        local RELAY=$(grep -i "mynetworks\|relay" /etc/postfix/main.cf | head -5)
        DETAILS="postfix 릴레이 설정:\n$RELAY"
        RES="M"
        DESC="메일 릴레이 설정 확인, 수동 확인 필요"
    else
        RES="N/A"
        DESC="메일 서비스 설정 파일(sendmail.cf/main.cf)이 존재하지 않아 해당 없음"
        DETAILS="sendmail.cf/main.cf: 없음"
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

    local DETAILS=""

    # sendmail 확인
    if [ -f /etc/mail/sendmail.cf ]; then
        # [FIX] 주석 행 제외
        local PRIVACY=$(grep -i "PrivacyOptions" /etc/mail/sendmail.cf | grep -v "^#")
        DETAILS="sendmail PrivacyOptions:\n$PRIVACY"

        # [FIX] goaway 옵션 포함 시 noexpn+novrfy 모두 적용됨
        if echo "$PRIVACY" | grep -qi "goaway\|noexpn.*novrfy\|novrfy.*noexpn"; then
            RES="Y"
            DESC="sendmail expn/vrfy 명령어가 제한되어 양호"
        else
            RES="N"
            DESC="sendmail expn/vrfy 명령어가 허용되어 취약"
        fi
    # postfix 확인
    elif [ -f /etc/postfix/main.cf ]; then
        local VRFY=$(grep -i "disable_vrfy_command" /etc/postfix/main.cf)
        DETAILS="postfix disable_vrfy_command:\n$VRFY"

        if echo "$VRFY" | grep -qi "yes"; then
            RES="Y"
            DESC="postfix vrfy 명령어가 제한되어 양호"
        else
            RES="N"
            DESC="postfix vrfy 명령어가 허용되어 취약"
        fi
    else
        RES="N/A"
        DESC="메일 서비스 설정 파일(sendmail.cf/main.cf)이 존재하지 않아 해당 없음"
        DETAILS="sendmail.cf/main.cf: 없음"
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

    local DETAILS=""

    if command -v named &>/dev/null; then
        local NAMED_VER=$(named -v 2>/dev/null)
        DETAILS="BIND 버전: $NAMED_VER"
        RES="M"
        DESC="DNS 서비스(BIND) 설치 확인, 수동 확인 필요"
    elif systemctl is-active named &>/dev/null; then
        DETAILS="named 서비스: 실행 중"
        RES="M"
        DESC="DNS 서비스(BIND) 설치 확인, 수동 확인 필요"
    else
        RES="N/A"
        DESC="DNS 서비스(named)가 미사용되어 해당 없음"
        DETAILS="named: 미실행"
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

    local NAMED_CONF=""
    # [FIX] /etc/bind/named.conf 경로 추가 (Debian/Ubuntu)
    if [ -f /etc/named.conf ]; then
        NAMED_CONF="/etc/named.conf"
    elif [ -f /etc/bind/named.conf ]; then
        NAMED_CONF="/etc/bind/named.conf"
    fi

    if [ -z "$NAMED_CONF" ]; then
        RES="N/A"
        DESC="DNS 설정 파일(named.conf)이 존재하지 않아 해당 없음"
        DT="named.conf: 없음"
    else
        # [FIX] 주석 행 제외
        local ALLOW_TRANSFER=$(grep -v "^[[:space:]]*#\|^[[:space:]]*//" "$NAMED_CONF" | grep -i "allow-transfer")

        if [ -z "$ALLOW_TRANSFER" ]; then
            RES="N"
            DESC="Zone Transfer 제한(allow-transfer)이 설정되지 않아 취약"
            DT="allow-transfer: not set"
        # [FIX] "specific" 제거, none 또는 특정 IP → Y, any → N
        elif echo "$ALLOW_TRANSFER" | grep -qi "none"; then
            RES="Y"
            DESC="Zone Transfer가 none으로 제한되어 양호"
            DT="$ALLOW_TRANSFER"
        elif echo "$ALLOW_TRANSFER" | grep -qi "any"; then
            RES="N"
            DESC="Zone Transfer가 모든 호스트(any)에 허용되어 취약"
            DT="$ALLOW_TRANSFER"
        else
            RES="Y"
            DESC="Zone Transfer가 특정 IP로 제한되어 양호"
            DT="$ALLOW_TRANSFER"
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

    local NAMED_CONF="/etc/named.conf"

    if [ ! -f "$NAMED_CONF" ]; then
        RES="N/A"
        DESC="DNS 설정 파일이 존재하지 않아 해당 없음"
        DT="$NAMED_CONF: 없음"
    else
        local ALLOW_UPDATE=$(grep -i "allow-update" "$NAMED_CONF")

        if [ -z "$ALLOW_UPDATE" ]; then
            RES="Y"
            DESC="DNS 동적 업데이트(allow-update)가 설정되지 않아 양호"
            DT="allow-update: not set"
        elif echo "$ALLOW_UPDATE" | grep -q "none"; then
            RES="Y"
            DESC="DNS 동적 업데이트가 none으로 제한되어 양호"
            DT="$ALLOW_UPDATE"
        else
            RES="M"
            DESC="DNS 동적 업데이트(allow-update) 설정 확인됨, 수동 확인 필요"
            DT="$ALLOW_UPDATE"
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

    local RUNNING=false
    local DETAILS=""

    # 프로세스 확인
    if pgrep -x "in.telnetd\|telnetd" &>/dev/null; then
        RUNNING=true
        DETAILS="telnetd 프로세스: 실행 중\n"
    fi

    # 포트 확인
    if ss -tuln 2>/dev/null | grep -q ":23 "; then
        RUNNING=true
        DETAILS="${DETAILS}포트 23: 사용 중\n"
    fi

    # systemd 서비스 확인
    if systemctl is-active telnet.socket &>/dev/null; then
        RUNNING=true
        DETAILS="${DETAILS}telnet.socket: 활성화\n"
    fi

    if $RUNNING; then
        RES="N"
        DESC="Telnet 서비스가 실행 중이어서 취약"
    else
        RES="Y"
        DESC="Telnet 서비스가 비활성화되어 양호"
        DETAILS="telnet: 미실행"
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

    local DETAILS=""

    # vsftpd 확인
    if [ -f /etc/vsftpd/vsftpd.conf ] || [ -f /etc/vsftpd.conf ]; then
        local VSFTPD_CONF=$(ls /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf 2>/dev/null | head -1)
        local BANNER=$(grep -i "ftpd_banner" "$VSFTPD_CONF" 2>/dev/null)
        DETAILS="vsftpd 배너: ${BANNER:-기본값}"
        RES="M"
        DESC="FTP 배너 설정이 확인됨, 수동 확인 필요"
    # proftpd 확인
    elif [ -f /etc/proftpd.conf ]; then
        local BANNER=$(grep -i "ServerIdent" /etc/proftpd.conf)
        DETAILS="proftpd ServerIdent: ${BANNER:-기본값}"
        RES="M"
        DESC="FTP 배너 설정이 확인됨, 수동 확인 필요"
    else
        RES="N/A"
        DESC="FTP 서비스 설정 파일이 존재하지 않아 해당 없음"
        DETAILS="vsftpd.conf/proftpd.conf: 없음"
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

    local RUNNING=false
    local DETAILS=""

    # FTP 프로세스 확인
    if pgrep -x "vsftpd\|proftpd\|pure-ftpd" &>/dev/null; then
        RUNNING=true
        DETAILS="FTP 프로세스: 실행 중\n"
    fi

    # 포트 21 확인
    if ss -tuln 2>/dev/null | grep -q ":21 "; then
        RUNNING=true
        DETAILS="${DETAILS}포트 21: 사용 중\n"
    fi

    if $RUNNING; then
        # SSL/TLS 설정 확인
        if [ -f /etc/vsftpd/vsftpd.conf ] || [ -f /etc/vsftpd.conf ]; then
            local VSFTPD_CONF=$(ls /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf 2>/dev/null | head -1)
            if grep -qi "ssl_enable=YES" "$VSFTPD_CONF" 2>/dev/null; then
                RES="Y"
                DESC="FTP SSL/TLS 암호화가 활성화되어 양호"
            else
                RES="N"
                DESC="FTP가 암호화 없이 실행 중이어서 취약"
            fi
        else
            RES="N"
            DESC="FTP가 암호화 없이 실행 중이어서 취약"
        fi
    else
        RES="Y"
        DESC="FTP 서비스가 비활성화되어 양호"
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
    local FTP_SHELL=$(grep "^ftp:" /etc/passwd 2>/dev/null | cut -d: -f7)

    if [ -z "$FTP_SHELL" ]; then
        RES="N/A"
        DESC="ftp 계정이 존재하지 않아 해당 없음"
        DT="ftp 계정: 없음"
    elif [[ "$FTP_SHELL" =~ (nologin|false) ]]; then
        RES="Y"
        DESC="ftp 계정 쉘이 nologin/false로 제한되어 양호"
        DT="ftp 쉘: $FTP_SHELL"
    else
        RES="N"
        DESC="ftp 계정에 로그인 가능한 쉘이 부여되어 취약"
        DT="ftp 쉘: $FTP_SHELL"
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

    local DETAILS=""
    local HAS_CONTROL=false

    # hosts.allow/deny 확인
    if grep -qi "vsftpd\|proftpd\|ftpd" /etc/hosts.allow 2>/dev/null; then
        HAS_CONTROL=true
        DETAILS="hosts.allow: FTP 설정 존재\n"
    fi

    if grep -qi "vsftpd\|proftpd\|ftpd" /etc/hosts.deny 2>/dev/null; then
        HAS_CONTROL=true
        DETAILS="${DETAILS}hosts.deny: FTP 설정 존재\n"
    fi

    # vsftpd tcp_wrappers 확인
    if [ -f /etc/vsftpd/vsftpd.conf ] || [ -f /etc/vsftpd.conf ]; then
        local VSFTPD_CONF=$(ls /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf 2>/dev/null | head -1)
        local TCP_WRAP=$(grep -i "tcp_wrappers" "$VSFTPD_CONF" 2>/dev/null)
        DETAILS="${DETAILS}vsftpd tcp_wrappers: ${TCP_WRAP:-not set}"
    fi

    if $HAS_CONTROL; then
        RES="Y"
        DESC="FTP 접근 제어(hosts.allow/deny)가 설정되어 양호"
    else
        RES="M"
        DESC="FTP 접근 제어 설정이 확인되지 않아, 수동 확인 필요"
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

    local FTPUSERS="/etc/vsftpd/ftpusers"
    [ ! -f "$FTPUSERS" ] && FTPUSERS="/etc/ftpusers"

    if [ ! -f "$FTPUSERS" ]; then
        RES="N/A"
        DESC="ftpusers 파일이 존재하지 않아 해당 없음"
        DT="ftpusers: 없음"
    else
        local ROOT_DENIED=$(grep "^root" "$FTPUSERS" 2>/dev/null)
        local CONTENT=$(cat "$FTPUSERS" | head -10)

        if [ -n "$ROOT_DENIED" ]; then
            RES="Y"
            DESC="root 계정이 ftpusers에 등록되어 FTP 접근이 차단되어 양호"
        else
            RES="N"
            DESC="root 계정이 ftpusers에 미등록되어 취약"
        fi
        DT="$FTPUSERS:\n$CONTENT"
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

    local RUNNING=false
    local DETAILS=""

    # snmpd 프로세스 확인
    if pgrep -x "snmpd" &>/dev/null; then
        RUNNING=true
        DETAILS="snmpd 프로세스: 실행 중\n"
    fi

    # systemd 서비스 확인
    if systemctl is-active snmpd &>/dev/null; then
        RUNNING=true
        DETAILS="${DETAILS}snmpd.service: 실행 중\n"
    fi

    # 포트 161 확인
    if ss -tuln 2>/dev/null | grep -q ":161 "; then
        RUNNING=true
        DETAILS="${DETAILS}포트 161: 사용 중\n"
    fi

    if $RUNNING; then
        RES="M"
        DESC="SNMP 서비스가 실행 중으로 확인됨, 수동 확인 필요"
    else
        RES="Y"
        DESC="SNMP 서비스가 비활성화되어 양호"
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

    local SNMP_CONF="/etc/snmp/snmpd.conf"

    if [ ! -f "$SNMP_CONF" ]; then
        if ! pgrep -x "snmpd" &>/dev/null; then
            RES="N/A"
            DESC="SNMP 서비스가 미사용 상태로 해당 없음"
            DT="snmpd.conf: 없음, snmpd: 미실행"
        else
            RES="M"
            DESC="SNMP 설정 파일 미존재, 수동 확인 필요"
            DT="snmpd.conf: 없음"
        fi
    else
        local V3_CONFIG=$(grep -iE "^rouser|^rwuser|^createUser" "$SNMP_CONF")
        local V1V2_CONFIG=$(grep -iE "^rocommunity|^rwcommunity" "$SNMP_CONF")

        if [ -n "$V3_CONFIG" ] && [ -z "$V1V2_CONFIG" ]; then
            RES="Y"
            DESC="SNMPv3만 사용 중이어서 양호"
            DT="SNMPv3 설정:\n$V3_CONFIG"
        elif [ -n "$V1V2_CONFIG" ]; then
            RES="N"
            DESC="취약한 SNMP 버전(v1/v2c)이 사용 중이어서 취약"
            DT="v1/v2c 설정:\n$V1V2_CONFIG"
        else
            RES="M"
            DESC="SNMP 버전 설정이 확인되지 않아, 수동 확인 필요"
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

    local SNMP_CONF="/etc/snmp/snmpd.conf"
    local WEAK_STRINGS="public private"

    if [ ! -f "$SNMP_CONF" ]; then
        RES="N/A"
        DESC="SNMP 설정 파일이 존재하지 않아 해당 없음"
        DT="snmpd.conf: 없음"
    else
        local COMMUNITIES=$(grep -iE "^rocommunity|^rwcommunity" "$SNMP_CONF" | awk '{print $2}')
        local HAS_WEAK=false

        for comm in $COMMUNITIES; do
            for weak in $WEAK_STRINGS; do
                if [ "$comm" == "$weak" ]; then
                    HAS_WEAK=true
                    break
                fi
            done
        done

        if [ -z "$COMMUNITIES" ]; then
            RES="Y"
            DESC="Community String이 미사용(SNMPv3)으로 설정되어 양호"
            DT="Community: 설정 없음"
        elif $HAS_WEAK; then
            RES="N"
            DESC="기본 Community String(public/private)이 사용 중이어서 취약"
            DT="Community: $COMMUNITIES"
        else
            # [FIX] 복잡성 자동 판단 불가 → M(수동)으로 변경
            RES="M"
            DESC="Community String이 설정되어 있으나 복잡성 확인됨, 수동 확인 필요"
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

    local SNMP_CONF="/etc/snmp/snmpd.conf"

    if [ ! -f "$SNMP_CONF" ]; then
        RES="N/A"
        DESC="SNMP 설정 파일이 존재하지 않아 해당 없음"
        DT="snmpd.conf: 없음"
    else
        local DETAILS=""
        local HAS_ISSUE=false

        # 접근 제어 설정 확인
        local ACCESS_CONTROL=$(grep -iE "^com2sec|^group|^access|^view" "$SNMP_CONF" | head -10)
        if [ -n "$ACCESS_CONTROL" ]; then
            DETAILS="접근 제어 설정:\n$ACCESS_CONTROL"
        fi

        # rocommunity/rwcommunity 네트워크 제한 확인
        local ROCOMM=$(grep -E "^rocommunity[[:space:]]" "$SNMP_CONF" 2>/dev/null)
        local RWCOMM=$(grep -E "^rwcommunity[[:space:]]" "$SNMP_CONF" 2>/dev/null)

        if [ -n "$ROCOMM" ] || [ -n "$RWCOMM" ]; then
            DETAILS="${DETAILS}\n--- Community 설정 ---"
            [ -n "$ROCOMM" ] && DETAILS="${DETAILS}\n$ROCOMM"
            [ -n "$RWCOMM" ] && DETAILS="${DETAILS}\n$RWCOMM"

            # 네트워크 제한 없이 설정된 경우 (community string만 있고 IP/대역 미지정)
            # 형식: rocommunity <string> [IP/network]
            while IFS= read -r line; do
                # 공백으로 분리했을 때 필드가 2개 이하면 네트워크 제한 없음
                local fields=$(echo "$line" | awk '{print NF}')
                if [ "$fields" -le 2 ]; then
                    HAS_ISSUE=true
                fi
            done <<< "$(echo -e "$ROCOMM\n$RWCOMM" | grep -v "^$")"
        fi

        if $HAS_ISSUE; then
            RES="N"
            DESC="SNMP community에 네트워크 접근 제한이 미설정되어 취약"
        elif [ -n "$ACCESS_CONTROL" ]; then
            RES="M"
            DESC="SNMP 접근 제어 설정이 확인됨, 수동 확인 필요"
        else
            RES="N"
            DESC="SNMP 접근 제어가 설정되지 않아 취약"
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

    local BANNER_FILES="/etc/motd /etc/issue /etc/issue.net"
    local HAS_BANNER=false
    local DETAILS=""

    for file in $BANNER_FILES; do
        if [ -f "$file" ] && [ -s "$file" ]; then
            local CONTENT=$(head -3 "$file")
            DETAILS="${DETAILS}${file}:\n$CONTENT\n\n"
            HAS_BANNER=true
        fi
    done

    # SSH 배너 확인
    local SSH_BANNER=$(grep -i "^Banner" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ -n "$SSH_BANNER" ] && [ "$SSH_BANNER" != "none" ]; then
        DETAILS="${DETAILS}SSH Banner: $SSH_BANNER"
        HAS_BANNER=true
    fi

    if $HAS_BANNER; then
        RES="Y"
        DESC="로그인 경고 메시지가 설정되어 양호"
    else
        RES="N"
        DESC="로그인 경고 메시지가 설정되지 않아 취약"
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

    local SUDOERS="/etc/sudoers"

    if [ ! -f "$SUDOERS" ]; then
        RES="N/A"
        DESC="sudoers 파일이 존재하지 않아 해당 없음"
        DT="$SUDOERS: 없음"
    else
        local HAS_ISSUE=false
        local DETAILS=""

        # 파일 권한 및 소유자 확인
        local OWNER=$(stat -c "%U" "$SUDOERS" 2>/dev/null)
        local PERM=$(stat -c "%a" "$SUDOERS" 2>/dev/null)

        if [ "$OWNER" != "root" ]; then
            HAS_ISSUE=true
            DETAILS="소유자: $OWNER (취약 - root 아님)\n"
        else
            DETAILS="소유자: $OWNER (양호)\n"
        fi

        if [ "$PERM" -gt 640 ] 2>/dev/null; then
            HAS_ISSUE=true
            DETAILS="${DETAILS}권한: $PERM (취약 - 640 초과)\n"
        else
            DETAILS="${DETAILS}권한: $PERM (양호)\n"
        fi

        # NOPASSWD 또는 ALL 권한 확인
        local NOPASSWD=$(grep -v "^#" "$SUDOERS" | grep "NOPASSWD")
        local ALL_ALL=$(grep -v "^#" "$SUDOERS" | grep "ALL=(ALL)")

        DETAILS="${DETAILS}NOPASSWD 설정: $([ -n "$NOPASSWD" ] && echo '있음' || echo '없음')\n"
        DETAILS="${DETAILS}ALL 권한: $([ -n "$ALL_ALL" ] && echo '있음' || echo '없음')"

        if $HAS_ISSUE; then
            RES="N"
            DESC="sudoers 파일 권한 또는 소유자가 기준(root, 640 이하)을 충족하지 않아 취약"
        else
            # [FIX] KISA 기준 충족(소유자 root + 권한 640 이하) 시 Y(양호) 판정
            RES="Y"
            DESC="sudoers 파일 소유자가 root이고 권한이 640 이하로 설정되어 양호"
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

    local DETAILS=""

    # OS 정보
    DETAILS="OS: $SYS_OS_NAME\n"
    DETAILS="${DETAILS}Kernel: $SYS_KN\n"

    # 패키지 업데이트 확인 (yum/dnf)
    if command -v dnf &>/dev/null; then
        local UPDATES=$(dnf check-update 2>/dev/null | grep -c "^\S")
        DETAILS="${DETAILS}사용 가능한 업데이트: ${UPDATES:-확인불가}개"
    elif command -v yum &>/dev/null; then
        local UPDATES=$(yum check-update 2>/dev/null | grep -c "^\S")
        DETAILS="${DETAILS}사용 가능한 업데이트: ${UPDATES:-확인불가}개"
    fi

    RES="M"
    DESC="보안 패치 적용 현황이 수집됨, 수동 확인 필요"
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

    local RUNNING=false
    local DETAILS=""

    # chronyd 확인
    if systemctl is-active chronyd &>/dev/null; then
        RUNNING=true
        DETAILS="chronyd: 실행 중\n"
        local CHRONY_SOURCES=$(chronyc sources 2>/dev/null | head -5)
        DETAILS="${DETAILS}$CHRONY_SOURCES"
    fi

    # ntpd 확인
    if systemctl is-active ntpd &>/dev/null; then
        RUNNING=true
        DETAILS="${DETAILS}ntpd: 실행 중\n"
    fi

    # timedatectl 확인
    if command -v timedatectl &>/dev/null; then
        local SYNC_STATUS=$(timedatectl show --property=NTPSynchronized --value 2>/dev/null)
        DETAILS="${DETAILS}NTP 동기화: $SYNC_STATUS"
        [ "$SYNC_STATUS" == "yes" ] && RUNNING=true
    fi

    if $RUNNING; then
        RES="Y"
        DESC="NTP 시각 동기화가 설정되어 양호"
    else
        RES="N"
        DESC="NTP 시각 동기화가 설정되지 않아 취약"
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

    local RSYSLOG_CONF="/etc/rsyslog.conf"
    local RSYSLOG_D="/etc/rsyslog.d"
    local DETAILS=""
    local AUTHLOG=""

    if [ -f "$RSYSLOG_CONF" ]; then
        # 주요 로그 설정 확인 (rsyslog.conf)
        AUTHLOG=$(grep -E "auth\.\*|authpriv\.\*" "$RSYSLOG_CONF" | head -3)
        local MESSAGES=$(grep -E "^\*\.info|^\*\.err" "$RSYSLOG_CONF" | head -3)

        DETAILS="rsyslog.conf 설정:\n$AUTHLOG\n$MESSAGES"
    fi

    # /etc/rsyslog.d/ 디렉토리 확인
    if [ -d "$RSYSLOG_D" ]; then
        local D_AUTHLOG=$(grep -rE "auth\.\*|authpriv\.\*" "$RSYSLOG_D"/*.conf 2>/dev/null | head -3)
        if [ -n "$D_AUTHLOG" ]; then
            DETAILS="${DETAILS}\n\nrsyslog.d 설정:\n$D_AUTHLOG"
            [ -z "$AUTHLOG" ] && AUTHLOG="$D_AUTHLOG"
        fi
    fi

    if [ -n "$AUTHLOG" ]; then
        RES="Y"
        DESC="시스템 로깅(rsyslog)이 정상 설정되어 양호"
    elif systemctl is-active rsyslog &>/dev/null; then
        RES="M"
        DESC="rsyslog 서비스가 실행 중이나 로그 설정 확인됨, 수동 확인 필요"
        DETAILS="${DETAILS}\nrsyslog: 실행 중"
    else
        RES="N"
        DESC="rsyslog 서비스가 실행되지 않아 취약"
        DETAILS="rsyslog: 미실행"
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

    local LOG_DIR="/var/log"
    local VULNERABLE=""
    local DETAILS=""

    # /var/log 디렉토리 권한 확인
    local DIR_PERM=$(stat -c "%a" "$LOG_DIR" 2>/dev/null)
    local DIR_OWNER=$(stat -c "%U" "$LOG_DIR" 2>/dev/null)
    DETAILS="$LOG_DIR: ${DIR_OWNER}:${DIR_PERM}\n"

    # 주요 로그 파일 권한 확인
    local LOG_FILES="messages secure auth.log cron maillog"
    for log in $LOG_FILES; do
        local LOG_PATH="$LOG_DIR/$log"
        if [ -f "$LOG_PATH" ]; then
            local perm=$(stat -c "%a" "$LOG_PATH" 2>/dev/null)
            local owner=$(stat -c "%U" "$LOG_PATH" 2>/dev/null)
            DETAILS="${DETAILS}${log}: ${owner}:${perm}\n"
            # [FIX] 비트마스크 기반 권한 비교로 변경 — group/other 쓰기 비트 직접 검사
            local group_perm=$(( (perm / 10) % 10 ))
            local other_perm=$((perm % 10))
            if [ "$owner" != "root" ] || [ $((group_perm & 2)) -ne 0 ] || [ $((other_perm & 2)) -ne 0 ] 2>/dev/null; then
                VULNERABLE="${VULNERABLE}${log} "
            fi
        fi
    done

    if [ -z "$VULNERABLE" ]; then
        RES="Y"
        DESC="로그 파일 권한이 기준에 맞게 설정되어 양호"
    else
        RES="N"
        DESC="로그 파일 권한이 기준(other 쓰기 제한)을 초과하여 취약"
    fi

    DT="$DETAILS취약: ${VULNERABLE:-없음}"

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
echo "  OS: $SYS_OS_NAME"
echo "  커널: $SYS_KN"
echo "  IP: $SYS_IP"
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
echo ""
echo "  ─────────────────────────────────────────────────────────"
echo ""
echo "  점검이 완료되었습니다!"
echo "  호스트: $SYS_HOST"
echo "  결과 파일: $OUTPUT_FILE"
echo ""

#================================================================
# Linux 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : Rocky Linux, Amazon Linux, CentOS, RHEL 등
# 항목  : U-01 ~ U-67 (67개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="Linux"
META_TYPE="Server"

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

    # 콘솔 출력
    case "$RES" in
        "Y")   echo -e "    [\033[32mY\033[0m] $CODE $NAME" ;;
        "N")   echo -e "    [\033[31mN\033[0m] $CODE $NAME" ;;
        "M")   echo -e "    [\033[33mM\033[0m] $CODE $NAME" ;;
        "N/A") echo -e "    [\033[90m-\033[0m] $CODE $NAME" ;;
        *)     echo -e "    [-] $CODE $NAME" ;;
    esac

    # XML 출력
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

# 출력 파일 경로
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
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

    # SSH 설정 확인
    local SSHD_CONFIG="/etc/ssh/sshd_config"

    if [ ! -f "$SSHD_CONFIG" ]; then
        RES="N/A"
        DESC="SSH 설정 파일이 존재하지 않아 해당 없음"
        DT="파일: $SSHD_CONFIG (없음)"
    else
        local PERMIT=$(grep -i "^PermitRootLogin" "$SSHD_CONFIG" 2>/dev/null | awk '{print $2}' | head -1)

        if [[ "${PERMIT,,}" == "no" ]]; then
            RES="Y"
            DESC="root 원격 접속이 차단(PermitRootLogin no)되어 양호"
            DT="PermitRootLogin: $PERMIT"
        elif [ -z "$PERMIT" ]; then
            RES="N"
            DESC="PermitRootLogin 설정이 없어 기본값(yes)으로 허용되어 취약"
            DT="PermitRootLogin: not set (default: yes)"
        else
            RES="N"
            DESC="root 원격 접속이 허용(PermitRootLogin $PERMIT)되어 취약"
            DT="PermitRootLogin: $PERMIT"
        fi
    fi

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

    local ISSUES=""
    local DETAILS=""

    # /etc/login.defs 확인
    local PASS_MAX_DAYS=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    local PASS_MIN_DAYS=$(grep "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    DETAILS="PASS_MAX_DAYS: ${PASS_MAX_DAYS:-not set}\nPASS_MIN_DAYS: ${PASS_MIN_DAYS:-not set}"

    # /etc/security/pwquality.conf 확인
    local MINLEN=""
    if [ -f /etc/security/pwquality.conf ]; then
        MINLEN=$(grep "^minlen" /etc/security/pwquality.conf 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
        local DCREDIT=$(grep "^dcredit" /etc/security/pwquality.conf 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
        local UCREDIT=$(grep "^ucredit" /etc/security/pwquality.conf 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
        local LCREDIT=$(grep "^lcredit" /etc/security/pwquality.conf 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
        local OCREDIT=$(grep "^ocredit" /etc/security/pwquality.conf 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
        DETAILS="$DETAILS\nminlen: ${MINLEN:-not set}\ndcredit: ${DCREDIT:-not set}\nucredit: ${UCREDIT:-not set}\nlcredit: ${LCREDIT:-not set}\nocredit: ${OCREDIT:-not set}"
    fi

    # 판단
    local IS_OK=true

    if [ -z "$PASS_MAX_DAYS" ] || [ "$PASS_MAX_DAYS" -gt 90 ] 2>/dev/null; then
        IS_OK=false
        ISSUES="${ISSUES}PASS_MAX_DAYS 미설정 또는 90일 초과, "
    fi

    # [FIX] PASS_MIN_DAYS 미설정 또는 1일 미만 검사 추가 (KISA 조치방법 "최소 사용 기간 1일")
    if [ -z "$PASS_MIN_DAYS" ] || [ "$PASS_MIN_DAYS" -lt 1 ] 2>/dev/null; then
        IS_OK=false
        ISSUES="${ISSUES}PASS_MIN_DAYS 미설정 또는 1일 미만, "
    fi

    if [ -z "$MINLEN" ] || [ "$MINLEN" -lt 8 ] 2>/dev/null; then
        IS_OK=false
        ISSUES="${ISSUES}최소 길이 미설정 또는 8자 미만, "
    fi

    if $IS_OK; then
        RES="Y"
        DESC="비밀번호 관리정책이 기준에 맞게 설정되어 양호"
    else
        RES="N"
        DESC="비밀번호 관리정책이 미흡(${ISSUES%%, })하여 취약"
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

    local DENY_VALUE=""
    local DETAILS=""

    # faillock.conf 확인 (RHEL 8+)
    if [ -f /etc/security/faillock.conf ]; then
        DENY_VALUE=$(grep "^deny" /etc/security/faillock.conf 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ')
        DETAILS="faillock.conf deny: ${DENY_VALUE:-not set}"
    fi

    # PAM 설정 확인
    if [ -z "$DENY_VALUE" ]; then
        DENY_VALUE=$(grep -E "pam_faillock.*deny=" /etc/pam.d/system-auth 2>/dev/null | grep -oP 'deny=\K[0-9]+' | head -1)
        if [ -n "$DENY_VALUE" ]; then
            DETAILS="pam_faillock deny: $DENY_VALUE"
        fi
    fi

    # pam_tally2 확인 (구버전)
    if [ -z "$DENY_VALUE" ]; then
        DENY_VALUE=$(grep -E "pam_tally2.*deny=" /etc/pam.d/system-auth 2>/dev/null | grep -oP 'deny=\K[0-9]+' | head -1)
        if [ -n "$DENY_VALUE" ]; then
            DETAILS="pam_tally2 deny: $DENY_VALUE"
        fi
    fi

    # 판단
    if [ -z "$DENY_VALUE" ]; then
        RES="N"
        DESC="계정 잠금 임계값이 설정되지 않아 취약"
        DT="deny: not set"
    # [FIX] deny=0은 잠금 비활성화이므로 취약 처리 (0<=10 통과 방지)
    elif [ "$DENY_VALUE" -eq 0 ] 2>/dev/null; then
        RES="N"
        DESC="계정 잠금 임계값이 0으로 잠금이 비활성화되어 취약"
        DT="$DETAILS (deny=0은 잠금 비활성화)"
    elif [ "$DENY_VALUE" -le 10 ] 2>/dev/null; then
        RES="Y"
        DESC="계정 잠금 임계값이 10회 이하로 설정되어 양호"
        DT="$DETAILS"
    else
        RES="N"
        DESC="계정 잠금 임계값이 10회를 초과하여 취약"
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

    # /etc/passwd 두 번째 필드 확인
    local UNPROTECTED=$(awk -F: '$2 != "x" && $2 != "" {print $1}' /etc/passwd 2>/dev/null)

    # /etc/shadow 파일 존재 여부
    local SHADOW_EXISTS="N"
    [ -f /etc/shadow ] && SHADOW_EXISTS="Y"

    if [ -z "$UNPROTECTED" ] && [ "$SHADOW_EXISTS" == "Y" ]; then
        RES="Y"
        DESC="/etc/shadow를 통해 비밀번호가 암호화 보호되어 양호"
        DT="/etc/passwd 두 번째 필드: x\n/etc/shadow: 존재함"
    else
        RES="N"
        DESC="비밀번호 파일이 쉐도우 방식으로 보호되지 않아 취약"
        DT="쉐도우 미사용 계정: ${UNPROTECTED:-없음}\n/etc/shadow: $([ "$SHADOW_EXISTS" == "Y" ] && echo '존재함' || echo '없음')"
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
    local UID0_ACCOUNTS=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd 2>/dev/null)

    if [ -z "$UID0_ACCOUNTS" ]; then
        RES="Y"
        DESC="root 외 UID=0 계정이 존재하지 않아 양호"
        DT="UID=0 계정: root만 존재"
    else
        RES="N"
        DESC="root 외 UID=0 계정($UID0_ACCOUNTS)이 존재하여 취약"
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

    local DETAILS=""
    local IS_RESTRICTED=false

    # PAM 모듈 설정 확인
    if grep -q "pam_wheel.so" /etc/pam.d/su 2>/dev/null; then
        local PAM_WHEEL=$(grep "pam_wheel.so" /etc/pam.d/su | grep -v "^#")
        if [ -n "$PAM_WHEEL" ]; then
            IS_RESTRICTED=true
            DETAILS="pam_wheel.so 설정됨\n"
        fi
    fi

    # wheel 그룹 확인
    local WHEEL_GROUP=$(grep "^wheel:" /etc/group 2>/dev/null)
    DETAILS="${DETAILS}wheel 그룹: ${WHEEL_GROUP:-없음}\n"

    # su 권한 확인
    local SU_PERM=$(ls -l /usr/bin/su 2>/dev/null | awk '{print $1, $3, $4}')
    DETAILS="${DETAILS}su 권한: ${SU_PERM:-확인불가}"

    if $IS_RESTRICTED; then
        RES="Y"
        DESC="su 명령어가 pam_wheel.so를 통해 특정 그룹에만 허용되어 양호"
    else
        RES="N"
        DESC="su 명령어가 모든 사용자에게 허용되어 취약"
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

    # 기본 불필요 계정 목록
    local UNNECESSARY="lp uucp nuucp"
    local FOUND_ACCOUNTS=""

    for acc in $UNNECESSARY; do
        if grep -q "^${acc}:" /etc/passwd 2>/dev/null; then
            FOUND_ACCOUNTS="${FOUND_ACCOUNTS}${acc} "
        fi
    done

    # 로그인 가능한 일반 계정 목록
    local LOGIN_ACCOUNTS=$(awk -F: '$3 >= 1000 && $7 !~ /nologin|false/ {print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ')

    if [ -z "$FOUND_ACCOUNTS" ]; then
        RES="M"
        DESC="기본 불필요 계정이 확인되지 않으나 로그인 가능 계정 존재, 수동 확인 필요"
        DT="확인된 불필요 계정: 없음\n로그인 가능 계정: ${LOGIN_ACCOUNTS:-없음}"
    else
        RES="N"
        DESC="불필요한 기본 계정($FOUND_ACCOUNTS)이 존재하여 취약"
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
    local ROOT_GROUP=$(grep "^root:" /etc/group 2>/dev/null)
    local ROOT_MEMBERS=$(echo "$ROOT_GROUP" | cut -d: -f4)

    if [ -z "$ROOT_MEMBERS" ]; then
        RES="Y"
        DESC="관리자 그룹(GID=0)에 불필요한 계정이 없어 양호"
        DT="root 그룹: $ROOT_GROUP"
    else
        RES="M"
        DESC="관리자 그룹(GID=0)에 계정($ROOT_MEMBERS)이 존재, 수동 확인 필요"
        DT="root 그룹: $ROOT_GROUP\n그룹 멤버: $ROOT_MEMBERS"
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

    # 사용 중인 GID 목록 (passwd 파일)
    local USED_GIDS=$(cut -d: -f4 /etc/passwd 2>/dev/null | sort -u)

    # group 파일의 GID 목록
    local ALL_GIDS=$(cut -d: -f3 /etc/group 2>/dev/null | sort -u)

    # 사용되지 않는 그룹 확인 (시스템 그룹 제외)
    local UNUSED_GROUPS=""
    while IFS=: read -r name pass gid members; do
        if [ "$gid" -ge 1000 ] 2>/dev/null; then
            if [ -z "$members" ] && ! echo "$USED_GIDS" | grep -q "^${gid}$"; then
                UNUSED_GROUPS="${UNUSED_GROUPS}${name}(GID:$gid) "
            fi
        fi
    done < /etc/group

    if [ -z "$UNUSED_GROUPS" ]; then
        RES="Y"
        DESC="사용되지 않는 불필요한 그룹이 존재하지 않아 양호"
        DT="사용되지 않는 그룹: 없음"
    else
        RES="M"
        DESC="사용되지 않는 그룹이 존재, 수동 확인 필요"
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
    local DUP_UIDS=$(awk -F: '{print $3}' /etc/passwd 2>/dev/null | sort | uniq -d)

    if [ -z "$DUP_UIDS" ]; then
        RES="Y"
        DESC="동일한 UID를 공유하는 계정이 존재하지 않아 양호"
        DT="중복 UID: 없음"
    else
        local DUP_ACCOUNTS=""
        for uid in $DUP_UIDS; do
            local accounts=$(awk -F: -v uid="$uid" '$3 == uid {print $1}' /etc/passwd | tr '\n' ',' | sed 's/,$//')
            DUP_ACCOUNTS="${DUP_ACCOUNTS}UID=$uid: $accounts\n"
        done
        RES="N"
        DESC="동일한 UID를 공유하는 계정이 존재하여 취약"
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

    # 로그인이 불필요한 계정 목록
    local NOLOGIN_ACCOUNTS="daemon bin sys adm listen nobody nobody4 noaccess diag operator games gopher"
    local VULNERABLE_ACCOUNTS=""

    for acc in $NOLOGIN_ACCOUNTS; do
        local shell=$(grep "^${acc}:" /etc/passwd 2>/dev/null | cut -d: -f7)
        if [ -n "$shell" ] && [[ ! "$shell" =~ (nologin|false) ]]; then
            VULNERABLE_ACCOUNTS="${VULNERABLE_ACCOUNTS}${acc}($shell) "
        fi
    done

    if [ -z "$VULNERABLE_ACCOUNTS" ]; then
        RES="Y"
        DESC="로그인 불필요 계정에 /bin/nologin 또는 /bin/false가 설정되어 양호"
        DT="취약 계정: 없음"
    else
        RES="N"
        DESC="로그인 불필요 계정에 로그인 가능한 쉘이 부여되어 취약"
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

    local TMOUT_VALUE=""
    local DETAILS=""

    # /etc/profile, /etc/bashrc, /etc/profile.d/*.sh 확인
    for profile_file in /etc/profile /etc/bashrc /etc/profile.d/*.sh; do
        if [ -f "$profile_file" ] && [ -z "$TMOUT_VALUE" ]; then
            local found=$(grep -E "^[[:space:]]*(export[[:space:]]+)?TMOUT=" "$profile_file" 2>/dev/null | head -1)
            if [ -n "$found" ]; then
                TMOUT_VALUE=$(echo "$found" | sed 's/.*TMOUT=//' | tr -d ' ')
                DETAILS="$profile_file TMOUT=$TMOUT_VALUE"
            fi
        fi
    done

    # 판단
    if [ -z "$TMOUT_VALUE" ]; then
        RES="N"
        DESC="세션 타임아웃(TMOUT)이 설정되지 않아 취약"
        DT="TMOUT: not set"
    # [FIX] TMOUT=0은 타임아웃 비활성화이므로 취약 처리 (0<=600 통과 방지)
    elif [ "$TMOUT_VALUE" -eq 0 ] 2>/dev/null; then
        RES="N"
        DESC="세션 타임아웃(TMOUT)이 0으로 비활성화되어 취약"
        DT="$DETAILS (TMOUT=0은 타임아웃 비활성화)"
    elif [ "$TMOUT_VALUE" -le 600 ] 2>/dev/null; then
        RES="Y"
        DESC="세션 타임아웃(TMOUT)이 600초 이하로 설정되어 양호"
        DT="$DETAILS (기준: 600초 이하)"
    else
        RES="N"
        DESC="세션 타임아웃(TMOUT)이 600초를 초과하여 취약"
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

    local DETAILS=""
    local HAS_WEAK=false

    # /etc/shadow에서 암호화 알고리즘 확인
    local ENCRYPT_TYPES=$(awk -F: '$2 ~ /^\$/ {print substr($2,1,3)}' /etc/shadow 2>/dev/null | sort | uniq)
    DETAILS="사용 중인 알고리즘: "

    for type in $ENCRYPT_TYPES; do
        case "$type" in
            '$1$') DETAILS="${DETAILS}MD5(취약) "; HAS_WEAK=true ;;
            '$5$') DETAILS="${DETAILS}SHA-256 " ;;
            '$6$') DETAILS="${DETAILS}SHA-512 " ;;
            '$y$') DETAILS="${DETAILS}yescrypt " ;;
            *) DETAILS="${DETAILS}${type} " ;;
        esac
    done

    # /etc/login.defs 확인
    local ENCRYPT_METHOD=$(grep "^ENCRYPT_METHOD" /etc/login.defs 2>/dev/null | awk '{print $2}')
    DETAILS="${DETAILS}\nENCRYPT_METHOD: ${ENCRYPT_METHOD:-not set}"

    if $HAS_WEAK; then
        RES="N"
        DESC="취약한 암호화 알고리즘(MD5)이 사용되고 있어 취약"
    else
        RES="Y"
        DESC="안전한 암호화 알고리즘(SHA-256 이상)이 사용되어 양호"
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
    local ROOT_PATH=$(su - root -c 'echo $PATH' 2>/dev/null)
    local HAS_DOT=false

    # [FIX] 정규식에서 :\.$, ^:.*:$ 패턴 제거 — KISA 기준 "맨 앞이나 중간"만 취약
    if echo "$ROOT_PATH" | grep -qE '^\.|:\.:'; then
        HAS_DOT=true
    fi

    # root 홈 디렉토리 권한 확인
    local ROOT_HOME_PERM=$(stat -c "%a" /root 2>/dev/null)

    if $HAS_DOT; then
        RES="N"
        DESC="root PATH 환경변수에 현재 디렉토리(.)가 포함되어 취약"
        DT="PATH: $ROOT_PATH\nroot 홈 권한: $ROOT_HOME_PERM"
    elif [ "$ROOT_HOME_PERM" -gt 750 ] 2>/dev/null; then
        RES="N"
        DESC="root 홈 디렉토리 권한이 기준(750)을 초과하여 취약"
        DT="root 홈 권한: $ROOT_HOME_PERM (기준: 750 이하)"
    else
        RES="Y"
        DESC="PATH 환경변수에 현재 디렉토리(.)가 없고 root 홈 디렉토리 권한이 기준 이내로 설정되어 양호"
        DT="PATH: $ROOT_PATH\nroot 홈 권한: $ROOT_HOME_PERM"
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

    # 소유자가 없는 파일 확인 (주요 디렉토리만)
    local NOOWNER=$(find /etc /var /tmp -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -10)

    if [ -z "$NOOWNER" ]; then
        RES="Y"
        DESC="소유자가 존재하지 않는 파일 및 디렉토리가 없어 양호"
        DT="소유자 없는 파일: 없음"
    else
        RES="N"
        DESC="소유자가 존재하지 않는 파일 및 디렉토리가 발견되어 취약"
        DT="소유자 없는 파일:\n$NOOWNER"
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

    local TARGET="/etc/passwd"

    if [ ! -f "$TARGET" ]; then
        RES="N/A"
        DESC="/etc/passwd 파일이 존재하지 않아 해당 없음"
        DT="파일: $TARGET (없음)"
    else
        local PERM=$(stat -c "%a" "$TARGET" 2>/dev/null)
        local OWNER=$(stat -c "%U" "$TARGET" 2>/dev/null)

        if [ "$OWNER" == "root" ] && [ "$PERM" -le 644 ] 2>/dev/null; then
            RES="Y"
            DESC="/etc/passwd 파일 소유자가 root이고 권한이 기준(644) 이하로 설정되어 양호"
        else
            RES="N"
            DESC="/etc/passwd 파일 소유자 또는 권한이 기준(root 소유, 644 이하)에 맞지 않아 취약"
        fi
        DT="파일: $TARGET\n소유자: $OWNER\n권한: $PERM"
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

    local VULNERABLE=""
    local TARGETS="/etc/rc.d/init.d /etc/init.d /etc/rc.local"

    for target in $TARGETS; do
        if [ -e "$target" ]; then
            # 심볼릭 링크인 경우 실제 파일 경로 확인
            local real_target="$target"
            if [ -L "$target" ]; then
                real_target=$(readlink -f "$target" 2>/dev/null)
                [ -z "$real_target" ] && continue
            fi

            local perm=$(stat -c "%a" "$real_target" 2>/dev/null)
            local owner=$(stat -c "%U" "$real_target" 2>/dev/null)
            # [FIX] group 쓰기 권한도 검사 추가 (KISA "일반 사용자의 쓰기 권한" = group + other)
            local group_perm=$(( (perm / 10) % 10 ))
            local other_perm=$((perm % 10))
            if [ "$owner" != "root" ] || [ $((group_perm & 2)) -ne 0 ] || [ $((other_perm & 2)) -ne 0 ] 2>/dev/null; then
                VULNERABLE="${VULNERABLE}${target}(${owner}:${perm}) "
            fi

            # [FIX] 디렉토리인 경우 내부 개별 스크립트 파일도 순회 점검
            if [ -d "$real_target" ]; then
                for script_file in "$real_target"/*; do
                    [ -f "$script_file" ] || continue
                    local s_perm=$(stat -c "%a" "$script_file" 2>/dev/null)
                    local s_owner=$(stat -c "%U" "$script_file" 2>/dev/null)
                    local s_group_perm=$(( (s_perm / 10) % 10 ))
                    local s_other_perm=$((s_perm % 10))
                    if [ "$s_owner" != "root" ] || [ $((s_group_perm & 2)) -ne 0 ] || [ $((s_other_perm & 2)) -ne 0 ]; then
                        VULNERABLE="${VULNERABLE}${script_file}(${s_owner}:${s_perm}) "
                    fi
                done
            fi
        fi
    done

    # 검사 대상 목록 생성
    local CHECKED_LIST=""
    for target in $TARGETS; do
        if [ -e "$target" ]; then
            local real_target="$target"
            if [ -L "$target" ]; then
                real_target=$(readlink -f "$target" 2>/dev/null)
                [ -z "$real_target" ] && continue
            fi
            local perm=$(stat -c "%a" "$real_target" 2>/dev/null)
            local owner=$(stat -c "%U" "$real_target" 2>/dev/null)
            CHECKED_LIST="${CHECKED_LIST}  - ${target} (${owner}:${perm})\n"
        fi
    done

    if [ -z "$VULNERABLE" ]; then
        RES="Y"
        DESC="시스템 시작 스크립트의 소유자 및 권한이 기준에 맞게 설정되어 양호"
        DT="[검사 대상]\n${CHECKED_LIST}\n[취약 파일]\n없음"
    else
        RES="N"
        DESC="시스템 시작 스크립트의 소유자 또는 권한이 기준에 맞지 않아 취약"
        DT="[검사 대상]\n${CHECKED_LIST}\n[취약 파일]\n$VULNERABLE"
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

    local TARGET="/etc/shadow"

    if [ ! -f "$TARGET" ]; then
        RES="N/A"
        DESC="/etc/shadow 파일이 존재하지 않아 해당 없음"
        DT="파일: $TARGET (없음)"
    else
        local PERM=$(stat -c "%a" "$TARGET" 2>/dev/null)
        local OWNER=$(stat -c "%U" "$TARGET" 2>/dev/null)

        if [ "$OWNER" == "root" ] && [ "$PERM" -le 400 ] 2>/dev/null; then
            RES="Y"
            DESC="/etc/shadow 파일 소유자가 root이고 권한이 기준(400) 이하로 설정되어 양호"
        else
            RES="N"
            DESC="/etc/shadow 파일 소유자 또는 권한이 기준(root 소유, 400 이하)에 맞지 않아 취약"
        fi
        DT="파일: $TARGET\n소유자: $OWNER\n권한: $PERM (기준: 400 이하)"
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

    local TARGET="/etc/hosts"

    if [ ! -f "$TARGET" ]; then
        RES="N/A"
        DESC="/etc/hosts 파일이 존재하지 않아 해당 없음"
        DT="파일: $TARGET (없음)"
    else
        local PERM=$(stat -c "%a" "$TARGET" 2>/dev/null)
        local OWNER=$(stat -c "%U" "$TARGET" 2>/dev/null)

        if [ "$OWNER" == "root" ] && [ "$PERM" -le 644 ] 2>/dev/null; then
            RES="Y"
            DESC="/etc/hosts 파일 소유자가 root이고 권한이 기준(644) 이하로 설정되어 양호"
        else
            RES="N"
            DESC="/etc/hosts 파일 소유자 또는 권한이 기준(root 소유, 644 이하)에 맞지 않아 취약"
        fi
        DT="파일: $TARGET\n소유자: $OWNER\n권한: $PERM"
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

    local TARGETS="/etc/inetd.conf /etc/xinetd.conf"
    local FOUND=false
    local VULNERABLE=""
    local DETAILS=""

    for target in $TARGETS; do
        if [ -f "$target" ]; then
            FOUND=true
            local perm=$(stat -c "%a" "$target" 2>/dev/null)
            local owner=$(stat -c "%U" "$target" 2>/dev/null)
            DETAILS="${DETAILS}${target}: ${owner}:${perm}\n"
            if [ "$owner" != "root" ] || [ "$perm" -gt 600 ] 2>/dev/null; then
                VULNERABLE="${VULNERABLE}${target} "
            fi
        fi
    done

    if ! $FOUND; then
        RES="N/A"
        DESC="inetd/xinetd 설정 파일이 존재하지 않아 해당 없음"
        DT="(x)inetd.conf: 미사용"
    elif [ -z "$VULNERABLE" ]; then
        RES="Y"
        DESC="(x)inetd.conf 파일 소유자가 root이고 권한이 기준(600) 이하로 설정되어 양호"
        DT="$DETAILS"
    else
        RES="N"
        DESC="(x)inetd.conf 파일 소유자 또는 권한이 기준(root 소유, 600 이하)에 맞지 않아 취약"
        DT="$DETAILS취약 파일: $VULNERABLE"
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

    local TARGETS="/etc/rsyslog.conf /etc/syslog.conf"
    local FOUND=false
    local VULNERABLE=""
    local DETAILS=""

    for target in $TARGETS; do
        if [ -f "$target" ]; then
            FOUND=true
            local perm=$(stat -c "%a" "$target" 2>/dev/null)
            local owner=$(stat -c "%U" "$target" 2>/dev/null)
            DETAILS="${DETAILS}${target}: ${owner}:${perm}\n"
            # [FIX] bin, sys 소유자도 허용 (KISA "소유자가 root 또는 bin, sys")
            if [ "$owner" != "root" ] && [ "$owner" != "bin" ] && [ "$owner" != "sys" ] || [ "$perm" -gt 640 ] 2>/dev/null; then
                VULNERABLE="${VULNERABLE}${target} "
            fi
        fi
    done

    if ! $FOUND; then
        RES="N/A"
        DESC="syslog 설정 파일이 존재하지 않아 해당 없음"
        DT="(r)syslog.conf: 없음"
    elif [ -z "$VULNERABLE" ]; then
        RES="Y"
        DESC="syslog 설정 파일 소유자 및 권한이 기준(root/bin/sys 소유, 640 이하)에 맞게 설정되어 양호"
        DT="$DETAILS"
    else
        RES="N"
        DESC="syslog 설정 파일 소유자 또는 권한이 기준(root/bin/sys 소유, 640 이하)에 맞지 않아 취약"
        DT="$DETAILS취약 파일: $VULNERABLE"
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

    local TARGET="/etc/services"

    if [ ! -f "$TARGET" ]; then
        RES="N/A"
        DESC="/etc/services 파일이 존재하지 않아 해당 없음"
        DT="파일: $TARGET (없음)"
    else
        local PERM=$(stat -c "%a" "$TARGET" 2>/dev/null)
        local OWNER=$(stat -c "%U" "$TARGET" 2>/dev/null)

        # [FIX] KISA 기준 "소유자가 root(또는 bin, sys)" — bin, sys 소유자 허용 추가
        if { [ "$OWNER" == "root" ] || [ "$OWNER" == "bin" ] || [ "$OWNER" == "sys" ]; } && [ "$PERM" -le 644 ] 2>/dev/null; then
            RES="Y"
            DESC="/etc/services 파일 소유자 및 권한이 기준(root/bin/sys 소유, 644 이하)에 맞게 설정되어 양호"
        else
            RES="N"
            DESC="/etc/services 파일 소유자 또는 권한이 기준(root/bin/sys 소유, 644 이하)에 맞지 않아 취약"
        fi
        DT="파일: $TARGET\n소유자: $OWNER\n권한: $PERM"
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
    local SUID_FILES=$(find /usr /bin /sbin -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -20)
    local COUNT=$(echo "$SUID_FILES" | grep -c .)

    RES="M"
    DESC="SUID/SGID 설정 파일 ${COUNT}개 발견, 수동 확인 필요"
    DT="SUID/SGID 파일 목록:\n$SUID_FILES\n...(상위 20개만 표시)"

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

    local TARGETS="/etc/profile /etc/bashrc /root/.bashrc /root/.bash_profile"
    local VULNERABLE=""
    local DETAILS=""

    for target in $TARGETS; do
        if [ -f "$target" ]; then
            local perm=$(stat -c "%a" "$target" 2>/dev/null)
            local owner=$(stat -c "%U" "$target" 2>/dev/null)
            DETAILS="${DETAILS}${target}: ${owner}:${perm}\n"
            if [ "$owner" != "root" ] || [ "$perm" -gt 644 ] 2>/dev/null; then
                VULNERABLE="${VULNERABLE}${target} "
            fi
        fi
    done

    # [FIX] UID>=1000 일반 사용자 홈 디렉토리 환경변수 파일 점검 추가
    local ENV_FILES=".profile .bashrc .bash_profile .kshrc .cshrc .login"
    while IFS=: read -r uname _ uid _ _ homedir _; do
        # nfsnobody, nobody 제외, UID >= 1000 일반 사용자만 대상
        [ "$uid" -ge 1000 ] 2>/dev/null || continue
        [ "$uname" == "nfsnobody" ] && continue
        [ "$uname" == "nobody" ] && continue
        [ -d "$homedir" ] || continue

        for ef in $ENV_FILES; do
            local efile="${homedir}/${ef}"
            [ -f "$efile" ] || continue
            local eperm=$(stat -c "%a" "$efile" 2>/dev/null)
            local eowner=$(stat -c "%U" "$efile" 2>/dev/null)
            DETAILS="${DETAILS}${efile}: ${eowner}:${eperm}\n"
            # [FIX] 소유자가 해당 사용자 또는 root이고, 권한이 644 이하(group/other 쓰기 없음)면 양호
            if { [ "$eowner" != "$uname" ] && [ "$eowner" != "root" ]; } || [ "$eperm" -gt 644 ] 2>/dev/null; then
                VULNERABLE="${VULNERABLE}${efile} "
            fi
        done
    done < /etc/passwd

    if [ -z "$VULNERABLE" ]; then
        RES="Y"
        DESC="환경변수 파일 소유자 및 권한(644 이하)이 기준에 맞게 설정되어 양호"
        DT="$DETAILS"
    else
        RES="N"
        DESC="환경변수 파일 소유자 또는 권한이 기준(644)을 초과하여 취약"
        DT="$DETAILS취약 파일: $VULNERABLE"
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

    # [FIX] 검사 범위를 / 전체로 확장 (로컬 파일시스템만)
    local SEARCH_DIRS="/"

    # [FIX] -xdev 추가, /proc /sys /dev prune, 심볼릭 링크 제외
    local WW_FILES=$(find / -xdev \( -path /proc -o -path /sys -o -path /dev \) -prune -o -type f -perm -0002 ! -type l -print 2>/dev/null | head -20)
    local WW_COUNT=$(echo "$WW_FILES" | grep -c . 2>/dev/null)
    [ -z "$WW_FILES" ] && WW_COUNT=0

    if [ "$WW_COUNT" -eq 0 ]; then
        RES="Y"
        DESC="world writable 파일이 존재하지 않아 양호"
        DT="[검사 범위]\n  로컬 파일시스템 전체 (-xdev)\n  제외: /proc, /sys, /dev\n\n[world writable 파일]\n없음"
    else
        # [FIX] N → M 변경: KISA "관리자 인지 시 양호"이므로 자동 Y/N 불가
        RES="M"
        DESC="world writable 파일 ${WW_COUNT}개 존재, 수동 확인 필요"
        DT="[검사 범위]\n  로컬 파일시스템 전체 (-xdev)\n  제외: /proc, /sys, /dev\n\n[world writable 파일] (최대 20개 표시)\n$WW_FILES"
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
    local EXCLUDE_PATHS="/dev, /proc, /sys, /run, /selinux"

    # /dev 외부의 device 파일 검색 (가상 파일시스템 제외)
    local DEV_FILES=$(find / \
        -path /dev -prune -o \
        -path /proc -prune -o \
        -path /sys -prune -o \
        -path /run -prune -o \
        -path /selinux -prune -o \
        \( -type b -o -type c \) -print 2>/dev/null | head -10)
    local DEV_COUNT=$(find / \
        -path /dev -prune -o \
        -path /proc -prune -o \
        -path /sys -prune -o \
        -path /run -prune -o \
        -path /selinux -prune -o \
        \( -type b -o -type c \) -print 2>/dev/null | wc -l)

    if [ -z "$DEV_FILES" ]; then
        RES="Y"
        DESC="/dev 외부에 device 파일이 존재하지 않아 양호"
        DT="[검사 범위]\n  전체 파일시스템 (/ 기준)\n\n[제외 경로]\n  $EXCLUDE_PATHS\n\n[비정상 device 파일]\n없음"
    else
        RES="N"
        DESC="/dev 외부에 device 파일이 ${DEV_COUNT}개 존재하여 취약"
        DT="[검사 범위]\n  전체 파일시스템 (/ 기준)\n\n[제외 경로]\n  $EXCLUDE_PATHS\n\n[비정상 device 파일] (최대 10개 표시)\n$DEV_FILES"
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

    local VULNERABLE=""
    local DETAILS=""

    # /etc/hosts.equiv 확인
    if [ -f /etc/hosts.equiv ]; then
        VULNERABLE="${VULNERABLE}/etc/hosts.equiv "
        DETAILS="${DETAILS}/etc/hosts.equiv: 존재\n"
    fi

    # 사용자 홈 디렉토리의 .rhosts 확인
    while IFS=: read -r user _ _ _ _ home _; do
        if [ -f "${home}/.rhosts" ] 2>/dev/null; then
            VULNERABLE="${VULNERABLE}${home}/.rhosts "
            DETAILS="${DETAILS}${home}/.rhosts: 존재\n"
        fi
    done < /etc/passwd

    if [ -z "$VULNERABLE" ]; then
        RES="Y"
        DESC=".rhosts, hosts.equiv 파일이 존재하지 않아 양호"
        DT="취약 파일: 없음"
    else
        RES="N"
        DESC=".rhosts, hosts.equiv 파일이 존재하여 취약"
        DT="$DETAILS"
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

    local DETAILS=""
    local HAS_RESTRICTION=false

    # hosts.allow / hosts.deny 확인
    if [ -f /etc/hosts.allow ]; then
        local ALLOW_CONTENT=$(grep -v "^#" /etc/hosts.allow | grep -v "^$" | head -5)
        if [ -n "$ALLOW_CONTENT" ]; then
            DETAILS="${DETAILS}hosts.allow:\n$ALLOW_CONTENT\n"
            HAS_RESTRICTION=true
        fi
    fi

    if [ -f /etc/hosts.deny ]; then
        local DENY_CONTENT=$(grep -v "^#" /etc/hosts.deny | grep -v "^$" | head -5)
        if [ -n "$DENY_CONTENT" ]; then
            DETAILS="${DETAILS}hosts.deny:\n$DENY_CONTENT\n"
            HAS_RESTRICTION=true
        fi
    fi

    # iptables/firewalld 확인
    if command -v firewall-cmd &>/dev/null; then
        local FW_STATUS=$(firewall-cmd --state 2>/dev/null)
        DETAILS="${DETAILS}firewalld: $FW_STATUS\n"
        [ "$FW_STATUS" == "running" ] && HAS_RESTRICTION=true
    fi

    # [FIX] iptables 규칙 확인 추가
    if command -v iptables &>/dev/null; then
        local IPT_RULES=$(iptables -L -n 2>/dev/null | grep -cv "^Chain\|^target\|^$")
        if [ "$IPT_RULES" -gt 0 ] 2>/dev/null; then
            DETAILS="${DETAILS}iptables: ${IPT_RULES}개 규칙\n"
            HAS_RESTRICTION=true
        fi
    fi

    # [FIX] nftables 규칙 확인 추가
    if command -v nft &>/dev/null; then
        local NFT_RULES=$(nft list ruleset 2>/dev/null | grep -c "rule")
        if [ "$NFT_RULES" -gt 0 ] 2>/dev/null; then
            DETAILS="${DETAILS}nftables: ${NFT_RULES}개 규칙\n"
            HAS_RESTRICTION=true
        fi
    fi

    if $HAS_RESTRICTION; then
        RES="Y"
        DESC="접속 IP 및 포트 제한이 설정되어 양호"
    else
        RES="N"
        DESC="접속 IP 및 포트 제한이 설정되지 않아 취약"
        # [FIX] N 판정 시에도 확인 결과 표시
        [ -z "$DETAILS" ] && DETAILS="hosts.allow: 설정 없음\nhosts.deny: 설정 없음\nfirewalld/iptables/nftables: 미사용"
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

    local TARGET="/etc/hosts.lpd"

    if [ ! -f "$TARGET" ]; then
        RES="N/A"
        DESC="/etc/hosts.lpd 파일이 존재하지 않아 해당 없음"
        DT="파일: $TARGET (없음)"
    else
        local PERM=$(stat -c "%a" "$TARGET" 2>/dev/null)
        local OWNER=$(stat -c "%U" "$TARGET" 2>/dev/null)

        if [ "$OWNER" == "root" ] && [ "$PERM" -le 600 ] 2>/dev/null; then
            RES="Y"
            DESC="/etc/hosts.lpd 파일 소유자가 root이고 권한이 600 이하로 설정되어 양호"
        else
            RES="N"
            DESC="/etc/hosts.lpd 파일 소유자 또는 권한이 기준(600)을 초과하여 취약"
        fi
        DT="파일: $TARGET\n소유자: $OWNER\n권한: $PERM"
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

    local UMASK_VALUE=""
    local DETAILS=""

    # /etc/profile 확인
    UMASK_VALUE=$(grep -i "^umask" /etc/profile 2>/dev/null | awk '{print $2}' | head -1)
    if [ -n "$UMASK_VALUE" ]; then
        DETAILS="/etc/profile UMASK=$UMASK_VALUE"
    fi

    # /etc/bashrc 확인
    if [ -z "$UMASK_VALUE" ]; then
        UMASK_VALUE=$(grep -i "^umask" /etc/bashrc 2>/dev/null | awk '{print $2}' | head -1)
        if [ -n "$UMASK_VALUE" ]; then
            DETAILS="/etc/bashrc UMASK=$UMASK_VALUE"
        fi
    fi

    # 현재 umask
    local CURRENT_UMASK=$(umask)
    DETAILS="${DETAILS}\n현재 UMASK: $CURRENT_UMASK"

    # 판단 (022 또는 027 권장)
    if [ "$UMASK_VALUE" == "022" ] || [ "$UMASK_VALUE" == "027" ] || [ "$CURRENT_UMASK" == "0022" ] || [ "$CURRENT_UMASK" == "0027" ]; then
        RES="Y"
        DESC="UMASK 값이 022 이상으로 설정되어 양호"
    else
        RES="N"
        DESC="UMASK 값이 022 미만으로 설정되어 취약"
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

    local VULNERABLE=""
    local DETAILS=""

    while IFS=: read -r user _ uid _ _ home _; do
        if [ "$uid" -ge 1000 ] 2>/dev/null && [ -d "$home" ]; then
            local perm=$(stat -c "%a" "$home" 2>/dev/null)
            local owner=$(stat -c "%U" "$home" 2>/dev/null)
            # other 쓰기 권한(2) 여부 확인 (가이드라인: 타 사용자 쓰기 권한 제거)
            local other_perm=$((perm % 10))
            if [ "$owner" != "$user" ] || [ $((other_perm & 2)) -ne 0 ] 2>/dev/null; then
                VULNERABLE="${VULNERABLE}${home}(${owner}:${perm}) "
            fi
            DETAILS="${DETAILS}${user}: ${home}(${owner}:${perm})\n"
        fi
    done < /etc/passwd

    if [ -z "$VULNERABLE" ]; then
        RES="Y"
        DESC="홈 디렉토리 소유자 및 권한이 기준에 맞게 설정되어 양호"
    else
        RES="N"
        DESC="홈 디렉토리 소유자 또는 권한(other 쓰기)이 기준을 초과하여 취약"
    fi
    DT="$DETAILS취약: ${VULNERABLE:-없음}"

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

    local MISSING=""
    local DETAILS=""

    while IFS=: read -r user _ uid _ _ home _; do
        if [ "$uid" -ge 1000 ] 2>/dev/null; then
            if [ ! -d "$home" ]; then
                MISSING="${MISSING}${user}:${home} "
            fi
        fi
    done < /etc/passwd

    if [ -z "$MISSING" ]; then
        RES="Y"
        DESC="모든 사용자의 홈 디렉토리가 존재하여 양호"
        DT="누락된 홈 디렉토리: 없음"
    else
        RES="N"
        DESC="존재하지 않는 홈 디렉토리가 있어 취약"
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
    local HIDDEN_FILES=$(find /home /root -name ".*" -type f 2>/dev/null | head -20)
    local COUNT=$(echo "$HIDDEN_FILES" | grep -c .)

    RES="M"
    DESC="홈 디렉토리 내 숨김 파일 ${COUNT}개 발견, 수동 확인 필요"
    DT="숨김 파일 목록:\n$HIDDEN_FILES\n...(상위 20개만 표시)"

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

    local RUNNING=false
    local DETAILS=""

    # 프로세스 확인
    if pgrep -x "fingerd" &>/dev/null; then
        RUNNING=true
        DETAILS="fingerd 프로세스: 실행 중\n"
    fi

    # 포트 확인
    if ss -tuln 2>/dev/null | grep -q ":79 "; then
        RUNNING=true
        DETAILS="${DETAILS}포트 79: 사용 중\n"
    fi

    if $RUNNING; then
        RES="N"
        DESC="Finger 서비스(fingerd)가 실행 중이어서 취약"
    else
        RES="Y"
        DESC="Finger 서비스(fingerd)가 비활성화되어 양호"
        DETAILS="fingerd: 미실행"
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

    local VULNERABLE=false
    local DETAILS=""

    # NFS exports 확인
    if [ -f /etc/exports ]; then
        local EXPORTS=$(cat /etc/exports | grep -v "^#" | grep -v "^$")
        if [ -n "$EXPORTS" ]; then
            DETAILS="NFS exports:\n$EXPORTS\n"
            if echo "$EXPORTS" | grep -q "no_root_squash\|insecure\|\*"; then
                VULNERABLE=true
            fi
        fi
    fi

    # Samba 확인
    if [ -f /etc/samba/smb.conf ]; then
        local GUEST=$(grep -i "guest ok\|public" /etc/samba/smb.conf | grep -i "yes")
        if [ -n "$GUEST" ]; then
            VULNERABLE=true
            DETAILS="${DETAILS}Samba guest 허용 설정 발견\n"
        fi
    fi

    if $VULNERABLE; then
        RES="N"
        DESC="NFS/Samba 익명 접근이 허용되어 취약"
    else
        RES="Y"
        DESC="NFS/Samba 익명 접근이 제한되어 양호"
    fi

    DT="${DETAILS:-공유 서비스 설정: 양호}"

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

    local RUNNING=""
    local DETAILS=""

    # 프로세스 확인
    for svc in rlogind rshd rexecd; do
        if pgrep -x "$svc" &>/dev/null; then
            RUNNING="${RUNNING}${svc} "
        fi
    done

    # [FIX] 포트 확인 결과를 판정에 반영 — 포트 열려있으면 RUNNING에 추가
    if ss -tuln 2>/dev/null | grep -qE ":512 |:513 |:514 "; then
        DETAILS="r 계열 포트 사용 중"
        [ -z "$RUNNING" ] && RUNNING="port(512/513/514) "
    fi

    if [ -n "$RUNNING" ]; then
        RES="N"
        DESC="r 계열 서비스(rlogin/rsh/rexec)가 실행 중이어서 취약"
        DT="실행 중: $RUNNING\n$DETAILS"
    else
        RES="Y"
        DESC="r 계열 서비스(rlogin/rsh/rexec)가 비활성화되어 양호"
        DT="r 계열 서비스: 미실행"
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

    local VULNERABLE=""
    local DETAILS=""

    # crontab 관련 파일/디렉토리 확인
    local TARGETS="/etc/crontab /etc/cron.allow /etc/cron.deny /var/spool/cron"

    for target in $TARGETS; do
        if [ -e "$target" ]; then
            local perm=$(stat -c "%a" "$target" 2>/dev/null)
            local owner=$(stat -c "%U" "$target" 2>/dev/null)
            DETAILS="${DETAILS}${target}: ${owner}:${perm}\n"
            if [ "$owner" != "root" ]; then
                VULNERABLE="${VULNERABLE}${target} "
            fi
        fi
    done

    if [ -z "$VULNERABLE" ]; then
        RES="Y"
        DESC="crontab 관련 파일 소유자가 root로 설정되어 양호"
    else
        RES="N"
        DESC="crontab 관련 파일 소유자가 root가 아니어서 취약"
    fi

    DT="$DETAILS취약: ${VULNERABLE:-없음}"

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

    local VULNERABLE_SVCS="echo discard daytime chargen"
    local RUNNING=""
    local DETAILS=""

    # [FIX] xinetd.d 개별 파일에서 disable 여부 확인 방식으로 변경
    for svc in $VULNERABLE_SVCS; do
        # xinetd.d 설정 확인
        for conf in /etc/xinetd.d/*; do
            [ -f "$conf" ] || continue
            if grep -q "service.*$svc" "$conf" 2>/dev/null; then
                if ! grep -q "disable.*=.*yes" "$conf" 2>/dev/null; then
                    RUNNING="${RUNNING}${svc}(xinetd) "
                fi
            fi
        done
        # [FIX] systemd 환경 확인 추가
        if systemctl is-active "${svc}.socket" &>/dev/null || systemctl is-active "${svc}@.service" &>/dev/null; then
            RUNNING="${RUNNING}${svc}(systemd) "
        fi
    done

    if [ -z "$RUNNING" ]; then
        RES="Y"
        DESC="DoS 취약 서비스(echo/discard/daytime/chargen)가 비활성화되어 양호"
        DT="echo, discard, daytime, chargen: 비활성"
    else
        RES="N"
        DESC="DoS 취약 서비스(echo/discard/daytime/chargen)가 활성화되어 취약"
        DT="활성화된 서비스: $RUNNING"
    fi

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

    local RUNNING=false
    local DETAILS=""

    # NFS 서비스 확인
    if systemctl is-active nfs-server &>/dev/null || systemctl is-active nfs &>/dev/null; then
        RUNNING=true
        DETAILS="NFS 서비스: 실행 중\n"
    fi

    # rpcbind 확인
    if systemctl is-active rpcbind &>/dev/null; then
        DETAILS="${DETAILS}rpcbind: 실행 중\n"
    fi

    # 포트 확인
    if ss -tuln 2>/dev/null | grep -q ":2049 "; then
        RUNNING=true
        DETAILS="${DETAILS}포트 2049: 사용 중\n"
    fi

    if $RUNNING; then
        RES="M"
        DESC="NFS 서비스가 실행 중, 수동 확인 필요"
    else
        RES="Y"
        DESC="NFS 서비스가 비활성화되어 양호"
        DETAILS="NFS: 미실행"
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

    if [ ! -f /etc/exports ]; then
        RES="N/A"
        DESC="NFS exports 파일이 존재하지 않아 해당 없음"
        DT="/etc/exports: 없음"
    else
        local EXPORTS=$(cat /etc/exports | grep -v "^#" | grep -v "^$")
        if [ -z "$EXPORTS" ]; then
            RES="Y"
            DESC="NFS 공유 설정이 비어 있어 양호"
            DT="/etc/exports: 비어있음"
        elif echo "$EXPORTS" | grep -q "\*"; then
            RES="N"
            DESC="NFS 접근 통제에 와일드카드(*)가 사용되어 취약"
            DT="/etc/exports:\n$EXPORTS"
        else
            RES="M"
            DESC="NFS 접근 통제 설정 확인, 수동 확인 필요"
            DT="/etc/exports:\n$EXPORTS"
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

    local RUNNING=false
    local DETAILS=""

    # autofs 서비스 확인
    if systemctl is-active autofs &>/dev/null; then
        RUNNING=true
        DETAILS="autofs: 실행 중"
    fi

    # automount 프로세스 확인
    if pgrep -x "automount" &>/dev/null; then
        RUNNING=true
        DETAILS="${DETAILS}\nautomount 프로세스: 실행 중"
    fi

    if $RUNNING; then
        RES="N"
        DESC="automountd 서비스가 실행 중이어서 취약"
    else
        RES="Y"
        DESC="automountd 서비스가 비활성화되어 양호"
        DETAILS="automount: 미실행"
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

    local RPC_SVCS="rpc.cmsd rpc.ttdbserverd sadmind rusersd walld sprayd rstatd rpc.nisd rexd rpc.pcnfsd rpc.statd rpc.ypupdated rpc.rquotad kcms_server cachefsd"
    local RUNNING=""

    for svc in $RPC_SVCS; do
        if pgrep -x "$svc" &>/dev/null; then
            RUNNING="${RUNNING}${svc} "
        fi
    done

    # rpcbind 상태 확인
    local RPCBIND_STATUS=""
    if systemctl is-active rpcbind &>/dev/null; then
        RPCBIND_STATUS="rpcbind: 실행 중"
    else
        RPCBIND_STATUS="rpcbind: 미실행"
    fi

    if [ -z "$RUNNING" ]; then
        RES="Y"
        DESC="불필요한 RPC 서비스가 비활성화되어 양호"
        DT="$RPCBIND_STATUS\n취약 RPC 서비스: 미실행"
    else
        RES="N"
        DESC="불필요한 RPC 서비스가 실행 중이어서 취약"
        DT="$RPCBIND_STATUS\n실행 중: $RUNNING"
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

    local RUNNING=false
    local DETAILS=""

    # NIS 서비스 확인
    for svc in ypserv ypbind yppasswdd ypxfrd; do
        if pgrep -x "$svc" &>/dev/null; then
            RUNNING=true
            DETAILS="${DETAILS}${svc}: 실행 중\n"
        fi
    done

    # systemd 서비스 확인
    if systemctl is-active ypbind &>/dev/null; then
        RUNNING=true
        DETAILS="${DETAILS}ypbind.service: 실행 중\n"
    fi

    if $RUNNING; then
        RES="N"
        DESC="NIS/NIS+ 서비스가 실행 중이어서 취약"
    else
        RES="Y"
        DESC="NIS/NIS+ 서비스가 비활성화되어 양호"
        DETAILS="NIS 서비스: 미실행"
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

    local RUNNING=""
    local DETAILS=""

    # tftp 확인
    # [FIX] pgrep -x에서 | 패턴 미지원 → 개별 호출로 분리
    if pgrep -x "in.tftpd" &>/dev/null || pgrep -x "tftpd" &>/dev/null || ss -tuln | grep -q ":69 "; then
        RUNNING="${RUNNING}tftp "
    fi

    # talk 확인
    # [FIX] pgrep -x에서 | 패턴 미지원 → 개별 호출로 분리
    if pgrep -x "in.talkd" &>/dev/null || pgrep -x "talkd" &>/dev/null || pgrep -x "in.ntalkd" &>/dev/null || pgrep -x "ntalkd" &>/dev/null || ss -tuln | grep -q ":517 \|:518 "; then
        RUNNING="${RUNNING}talk "
    fi

    if [ -z "$RUNNING" ]; then
        RES="Y"
        DESC="tftp, talk 서비스가 비활성화되어 양호"
        DT="tftp, talk: 미실행"
    else
        RES="N"
        DESC="tftp 또는 talk 서비스가 실행 중이어서 취약"
        DT="실행 중: $RUNNING"
    fi

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

    local DETAILS=""

    # sendmail 버전 확인
    if command -v sendmail &>/dev/null; then
        local SENDMAIL_VER=$(sendmail -d0.1 -bv root 2>&1 | head -1)
        DETAILS="sendmail: $SENDMAIL_VER"
        RES="M"
        DESC="메일 서비스 설치 확인, 수동 확인 필요"
    # postfix 버전 확인
    elif command -v postfix &>/dev/null; then
        local POSTFIX_VER=$(postconf -d mail_version 2>/dev/null | cut -d'=' -f2)
        DETAILS="postfix: $POSTFIX_VER"
        RES="M"
        DESC="메일 서비스 설치 확인, 수동 확인 필요"
    else
        RES="N/A"
        DESC="메일 서비스(sendmail/postfix)가 미설치되어 해당 없음"
        DETAILS="sendmail/postfix: 미설치"
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

    local SENDMAIL_PATH=$(which sendmail 2>/dev/null)

    if [ -z "$SENDMAIL_PATH" ]; then
        RES="N/A"
        DESC="sendmail이 미설치되어 해당 없음"
        DT="sendmail: 미설치"
    else
        local PERM=$(stat -c "%a" "$SENDMAIL_PATH" 2>/dev/null)
        local DETAILS="$SENDMAIL_PATH: $PERM"
        local HAS_ISSUE=false

        # SUID 비트 확인
        if [ $((PERM & 4000)) -ne 0 ]; then
            HAS_ISSUE=true
            DETAILS="${DETAILS}\nSUID 비트: 설정됨 (취약)"
        else
            DETAILS="${DETAILS}\nSUID 비트: 미설정 (양호)"
        fi

        # sendmail.cf PrivacyOptions 확인
        local SENDMAIL_CF="/etc/mail/sendmail.cf"
        if [ -f "$SENDMAIL_CF" ]; then
            local PRIVACY=$(grep -i "^O PrivacyOptions" "$SENDMAIL_CF" 2>/dev/null)
            if echo "$PRIVACY" | grep -qi "restrictqrun"; then
                DETAILS="${DETAILS}\nPrivacyOptions: restrictqrun 설정됨 (양호)"
            else
                HAS_ISSUE=true
                DETAILS="${DETAILS}\nPrivacyOptions: restrictqrun 미설정 (취약)"
            fi
        fi

        if $HAS_ISSUE; then
            RES="N"
            DESC="sendmail SUID 비트 또는 PrivacyOptions 설정이 미흡하여 취약"
        else
            RES="Y"
            DESC="sendmail SUID 비트 미설정 및 PrivacyOptions가 적절히 설정되어 양호"
        fi
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

    local DETAILS=""

    # sendmail.cf 확인
    if [ -f /etc/mail/sendmail.cf ]; then
        local RELAY=$(grep -i "R$\*" /etc/mail/sendmail.cf | head -3)
        DETAILS="sendmail.cf 릴레이 설정:\n$RELAY"
        RES="M"
        DESC="메일 릴레이 설정 확인, 수동 확인 필요"
    # postfix 확인
    elif [ -f /etc/postfix/main.cf ]; then
        local RELAY=$(grep -i "mynetworks\|relay" /etc/postfix/main.cf | head -5)
        DETAILS="postfix 릴레이 설정:\n$RELAY"
        RES="M"
        DESC="메일 릴레이 설정 확인, 수동 확인 필요"
    else
        RES="N/A"
        DESC="메일 서비스 설정 파일(sendmail.cf/main.cf)이 존재하지 않아 해당 없음"
        DETAILS="sendmail.cf/main.cf: 없음"
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

    local DETAILS=""

    # sendmail 확인
    if [ -f /etc/mail/sendmail.cf ]; then
        # [FIX] 주석 행 제외
        local PRIVACY=$(grep -i "PrivacyOptions" /etc/mail/sendmail.cf | grep -v "^#")
        DETAILS="sendmail PrivacyOptions:\n$PRIVACY"

        # [FIX] goaway 옵션 포함 시 noexpn+novrfy 모두 적용됨
        if echo "$PRIVACY" | grep -qi "goaway\|noexpn.*novrfy\|novrfy.*noexpn"; then
            RES="Y"
            DESC="sendmail expn/vrfy 명령어가 제한되어 양호"
        else
            RES="N"
            DESC="sendmail expn/vrfy 명령어가 허용되어 취약"
        fi
    # postfix 확인
    elif [ -f /etc/postfix/main.cf ]; then
        local VRFY=$(grep -i "disable_vrfy_command" /etc/postfix/main.cf)
        DETAILS="postfix disable_vrfy_command:\n$VRFY"

        if echo "$VRFY" | grep -qi "yes"; then
            RES="Y"
            DESC="postfix vrfy 명령어가 제한되어 양호"
        else
            RES="N"
            DESC="postfix vrfy 명령어가 허용되어 취약"
        fi
    else
        RES="N/A"
        DESC="메일 서비스 설정 파일(sendmail.cf/main.cf)이 존재하지 않아 해당 없음"
        DETAILS="sendmail.cf/main.cf: 없음"
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

    local DETAILS=""

    if command -v named &>/dev/null; then
        local NAMED_VER=$(named -v 2>/dev/null)
        DETAILS="BIND 버전: $NAMED_VER"
        RES="M"
        DESC="DNS 서비스(BIND) 설치 확인, 수동 확인 필요"
    elif systemctl is-active named &>/dev/null; then
        DETAILS="named 서비스: 실행 중"
        RES="M"
        DESC="DNS 서비스(BIND) 설치 확인, 수동 확인 필요"
    else
        RES="N/A"
        DESC="DNS 서비스(named)가 미사용되어 해당 없음"
        DETAILS="named: 미실행"
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

    local NAMED_CONF=""
    # [FIX] /etc/bind/named.conf 경로 추가 (Debian/Ubuntu)
    if [ -f /etc/named.conf ]; then
        NAMED_CONF="/etc/named.conf"
    elif [ -f /etc/bind/named.conf ]; then
        NAMED_CONF="/etc/bind/named.conf"
    fi

    if [ -z "$NAMED_CONF" ]; then
        RES="N/A"
        DESC="DNS 설정 파일(named.conf)이 존재하지 않아 해당 없음"
        DT="named.conf: 없음"
    else
        # [FIX] 주석 행 제외
        local ALLOW_TRANSFER=$(grep -v "^[[:space:]]*#\|^[[:space:]]*//" "$NAMED_CONF" | grep -i "allow-transfer")

        if [ -z "$ALLOW_TRANSFER" ]; then
            RES="N"
            DESC="Zone Transfer 제한(allow-transfer)이 설정되지 않아 취약"
            DT="allow-transfer: not set"
        # [FIX] "specific" 제거, none 또는 특정 IP → Y, any → N
        elif echo "$ALLOW_TRANSFER" | grep -qi "none"; then
            RES="Y"
            DESC="Zone Transfer가 none으로 제한되어 양호"
            DT="$ALLOW_TRANSFER"
        elif echo "$ALLOW_TRANSFER" | grep -qi "any"; then
            RES="N"
            DESC="Zone Transfer가 모든 호스트(any)에 허용되어 취약"
            DT="$ALLOW_TRANSFER"
        else
            RES="Y"
            DESC="Zone Transfer가 특정 IP로 제한되어 양호"
            DT="$ALLOW_TRANSFER"
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

    local NAMED_CONF="/etc/named.conf"

    if [ ! -f "$NAMED_CONF" ]; then
        RES="N/A"
        DESC="DNS 설정 파일이 존재하지 않아 해당 없음"
        DT="$NAMED_CONF: 없음"
    else
        local ALLOW_UPDATE=$(grep -i "allow-update" "$NAMED_CONF")

        if [ -z "$ALLOW_UPDATE" ]; then
            RES="Y"
            DESC="DNS 동적 업데이트(allow-update)가 설정되지 않아 양호"
            DT="allow-update: not set"
        elif echo "$ALLOW_UPDATE" | grep -q "none"; then
            RES="Y"
            DESC="DNS 동적 업데이트가 none으로 제한되어 양호"
            DT="$ALLOW_UPDATE"
        else
            RES="M"
            DESC="DNS 동적 업데이트(allow-update) 설정 확인됨, 수동 확인 필요"
            DT="$ALLOW_UPDATE"
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

    local RUNNING=false
    local DETAILS=""

    # 프로세스 확인
    if pgrep -x "in.telnetd\|telnetd" &>/dev/null; then
        RUNNING=true
        DETAILS="telnetd 프로세스: 실행 중\n"
    fi

    # 포트 확인
    if ss -tuln 2>/dev/null | grep -q ":23 "; then
        RUNNING=true
        DETAILS="${DETAILS}포트 23: 사용 중\n"
    fi

    # systemd 서비스 확인
    if systemctl is-active telnet.socket &>/dev/null; then
        RUNNING=true
        DETAILS="${DETAILS}telnet.socket: 활성화\n"
    fi

    if $RUNNING; then
        RES="N"
        DESC="Telnet 서비스가 실행 중이어서 취약"
    else
        RES="Y"
        DESC="Telnet 서비스가 비활성화되어 양호"
        DETAILS="telnet: 미실행"
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

    local DETAILS=""

    # vsftpd 확인
    if [ -f /etc/vsftpd/vsftpd.conf ] || [ -f /etc/vsftpd.conf ]; then
        local VSFTPD_CONF=$(ls /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf 2>/dev/null | head -1)
        local BANNER=$(grep -i "ftpd_banner" "$VSFTPD_CONF" 2>/dev/null)
        DETAILS="vsftpd 배너: ${BANNER:-기본값}"
        RES="M"
        DESC="FTP 배너 설정이 확인됨, 수동 확인 필요"
    # proftpd 확인
    elif [ -f /etc/proftpd.conf ]; then
        local BANNER=$(grep -i "ServerIdent" /etc/proftpd.conf)
        DETAILS="proftpd ServerIdent: ${BANNER:-기본값}"
        RES="M"
        DESC="FTP 배너 설정이 확인됨, 수동 확인 필요"
    else
        RES="N/A"
        DESC="FTP 서비스 설정 파일이 존재하지 않아 해당 없음"
        DETAILS="vsftpd.conf/proftpd.conf: 없음"
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

    local RUNNING=false
    local DETAILS=""

    # FTP 프로세스 확인
    if pgrep -x "vsftpd\|proftpd\|pure-ftpd" &>/dev/null; then
        RUNNING=true
        DETAILS="FTP 프로세스: 실행 중\n"
    fi

    # 포트 21 확인
    if ss -tuln 2>/dev/null | grep -q ":21 "; then
        RUNNING=true
        DETAILS="${DETAILS}포트 21: 사용 중\n"
    fi

    if $RUNNING; then
        # SSL/TLS 설정 확인
        if [ -f /etc/vsftpd/vsftpd.conf ] || [ -f /etc/vsftpd.conf ]; then
            local VSFTPD_CONF=$(ls /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf 2>/dev/null | head -1)
            if grep -qi "ssl_enable=YES" "$VSFTPD_CONF" 2>/dev/null; then
                RES="Y"
                DESC="FTP SSL/TLS 암호화가 활성화되어 양호"
            else
                RES="N"
                DESC="FTP가 암호화 없이 실행 중이어서 취약"
            fi
        else
            RES="N"
            DESC="FTP가 암호화 없이 실행 중이어서 취약"
        fi
    else
        RES="Y"
        DESC="FTP 서비스가 비활성화되어 양호"
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
    local FTP_SHELL=$(grep "^ftp:" /etc/passwd 2>/dev/null | cut -d: -f7)

    if [ -z "$FTP_SHELL" ]; then
        RES="N/A"
        DESC="ftp 계정이 존재하지 않아 해당 없음"
        DT="ftp 계정: 없음"
    elif [[ "$FTP_SHELL" =~ (nologin|false) ]]; then
        RES="Y"
        DESC="ftp 계정 쉘이 nologin/false로 제한되어 양호"
        DT="ftp 쉘: $FTP_SHELL"
    else
        RES="N"
        DESC="ftp 계정에 로그인 가능한 쉘이 부여되어 취약"
        DT="ftp 쉘: $FTP_SHELL"
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

    local DETAILS=""
    local HAS_CONTROL=false

    # hosts.allow/deny 확인
    if grep -qi "vsftpd\|proftpd\|ftpd" /etc/hosts.allow 2>/dev/null; then
        HAS_CONTROL=true
        DETAILS="hosts.allow: FTP 설정 존재\n"
    fi

    if grep -qi "vsftpd\|proftpd\|ftpd" /etc/hosts.deny 2>/dev/null; then
        HAS_CONTROL=true
        DETAILS="${DETAILS}hosts.deny: FTP 설정 존재\n"
    fi

    # vsftpd tcp_wrappers 확인
    if [ -f /etc/vsftpd/vsftpd.conf ] || [ -f /etc/vsftpd.conf ]; then
        local VSFTPD_CONF=$(ls /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf 2>/dev/null | head -1)
        local TCP_WRAP=$(grep -i "tcp_wrappers" "$VSFTPD_CONF" 2>/dev/null)
        DETAILS="${DETAILS}vsftpd tcp_wrappers: ${TCP_WRAP:-not set}"
    fi

    if $HAS_CONTROL; then
        RES="Y"
        DESC="FTP 접근 제어(hosts.allow/deny)가 설정되어 양호"
    else
        RES="M"
        DESC="FTP 접근 제어 설정이 확인되지 않아, 수동 확인 필요"
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

    local FTPUSERS="/etc/vsftpd/ftpusers"
    [ ! -f "$FTPUSERS" ] && FTPUSERS="/etc/ftpusers"

    if [ ! -f "$FTPUSERS" ]; then
        RES="N/A"
        DESC="ftpusers 파일이 존재하지 않아 해당 없음"
        DT="ftpusers: 없음"
    else
        local ROOT_DENIED=$(grep "^root" "$FTPUSERS" 2>/dev/null)
        local CONTENT=$(cat "$FTPUSERS" | head -10)

        if [ -n "$ROOT_DENIED" ]; then
            RES="Y"
            DESC="root 계정이 ftpusers에 등록되어 FTP 접근이 차단되어 양호"
        else
            RES="N"
            DESC="root 계정이 ftpusers에 미등록되어 취약"
        fi
        DT="$FTPUSERS:\n$CONTENT"
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

    local RUNNING=false
    local DETAILS=""

    # snmpd 프로세스 확인
    if pgrep -x "snmpd" &>/dev/null; then
        RUNNING=true
        DETAILS="snmpd 프로세스: 실행 중\n"
    fi

    # systemd 서비스 확인
    if systemctl is-active snmpd &>/dev/null; then
        RUNNING=true
        DETAILS="${DETAILS}snmpd.service: 실행 중\n"
    fi

    # 포트 161 확인
    if ss -tuln 2>/dev/null | grep -q ":161 "; then
        RUNNING=true
        DETAILS="${DETAILS}포트 161: 사용 중\n"
    fi

    if $RUNNING; then
        RES="M"
        DESC="SNMP 서비스가 실행 중으로 확인됨, 수동 확인 필요"
    else
        RES="Y"
        DESC="SNMP 서비스가 비활성화되어 양호"
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

    local SNMP_CONF="/etc/snmp/snmpd.conf"

    if [ ! -f "$SNMP_CONF" ]; then
        if ! pgrep -x "snmpd" &>/dev/null; then
            RES="N/A"
            DESC="SNMP 서비스가 미사용 상태로 해당 없음"
            DT="snmpd.conf: 없음, snmpd: 미실행"
        else
            RES="M"
            DESC="SNMP 설정 파일 미존재, 수동 확인 필요"
            DT="snmpd.conf: 없음"
        fi
    else
        local V3_CONFIG=$(grep -iE "^rouser|^rwuser|^createUser" "$SNMP_CONF")
        local V1V2_CONFIG=$(grep -iE "^rocommunity|^rwcommunity" "$SNMP_CONF")

        if [ -n "$V3_CONFIG" ] && [ -z "$V1V2_CONFIG" ]; then
            RES="Y"
            DESC="SNMPv3만 사용 중이어서 양호"
            DT="SNMPv3 설정:\n$V3_CONFIG"
        elif [ -n "$V1V2_CONFIG" ]; then
            RES="N"
            DESC="취약한 SNMP 버전(v1/v2c)이 사용 중이어서 취약"
            DT="v1/v2c 설정:\n$V1V2_CONFIG"
        else
            RES="M"
            DESC="SNMP 버전 설정이 확인되지 않아, 수동 확인 필요"
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

    local SNMP_CONF="/etc/snmp/snmpd.conf"
    local WEAK_STRINGS="public private"

    if [ ! -f "$SNMP_CONF" ]; then
        RES="N/A"
        DESC="SNMP 설정 파일이 존재하지 않아 해당 없음"
        DT="snmpd.conf: 없음"
    else
        local COMMUNITIES=$(grep -iE "^rocommunity|^rwcommunity" "$SNMP_CONF" | awk '{print $2}')
        local HAS_WEAK=false

        for comm in $COMMUNITIES; do
            for weak in $WEAK_STRINGS; do
                if [ "$comm" == "$weak" ]; then
                    HAS_WEAK=true
                    break
                fi
            done
        done

        if [ -z "$COMMUNITIES" ]; then
            RES="Y"
            DESC="Community String이 미사용(SNMPv3)으로 설정되어 양호"
            DT="Community: 설정 없음"
        elif $HAS_WEAK; then
            RES="N"
            DESC="기본 Community String(public/private)이 사용 중이어서 취약"
            DT="Community: $COMMUNITIES"
        else
            # [FIX] 복잡성 자동 판단 불가 → M(수동)으로 변경
            RES="M"
            DESC="Community String이 설정되어 있으나 복잡성 확인됨, 수동 확인 필요"
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

    local SNMP_CONF="/etc/snmp/snmpd.conf"

    if [ ! -f "$SNMP_CONF" ]; then
        RES="N/A"
        DESC="SNMP 설정 파일이 존재하지 않아 해당 없음"
        DT="snmpd.conf: 없음"
    else
        local DETAILS=""
        local HAS_ISSUE=false

        # 접근 제어 설정 확인
        local ACCESS_CONTROL=$(grep -iE "^com2sec|^group|^access|^view" "$SNMP_CONF" | head -10)
        if [ -n "$ACCESS_CONTROL" ]; then
            DETAILS="접근 제어 설정:\n$ACCESS_CONTROL"
        fi

        # rocommunity/rwcommunity 네트워크 제한 확인
        local ROCOMM=$(grep -E "^rocommunity[[:space:]]" "$SNMP_CONF" 2>/dev/null)
        local RWCOMM=$(grep -E "^rwcommunity[[:space:]]" "$SNMP_CONF" 2>/dev/null)

        if [ -n "$ROCOMM" ] || [ -n "$RWCOMM" ]; then
            DETAILS="${DETAILS}\n--- Community 설정 ---"
            [ -n "$ROCOMM" ] && DETAILS="${DETAILS}\n$ROCOMM"
            [ -n "$RWCOMM" ] && DETAILS="${DETAILS}\n$RWCOMM"

            # 네트워크 제한 없이 설정된 경우 (community string만 있고 IP/대역 미지정)
            # 형식: rocommunity <string> [IP/network]
            while IFS= read -r line; do
                # 공백으로 분리했을 때 필드가 2개 이하면 네트워크 제한 없음
                local fields=$(echo "$line" | awk '{print NF}')
                if [ "$fields" -le 2 ]; then
                    HAS_ISSUE=true
                fi
            done <<< "$(echo -e "$ROCOMM\n$RWCOMM" | grep -v "^$")"
        fi

        if $HAS_ISSUE; then
            RES="N"
            DESC="SNMP community에 네트워크 접근 제한이 미설정되어 취약"
        elif [ -n "$ACCESS_CONTROL" ]; then
            RES="M"
            DESC="SNMP 접근 제어 설정이 확인됨, 수동 확인 필요"
        else
            RES="N"
            DESC="SNMP 접근 제어가 설정되지 않아 취약"
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

    local BANNER_FILES="/etc/motd /etc/issue /etc/issue.net"
    local HAS_BANNER=false
    local DETAILS=""

    for file in $BANNER_FILES; do
        if [ -f "$file" ] && [ -s "$file" ]; then
            local CONTENT=$(head -3 "$file")
            DETAILS="${DETAILS}${file}:\n$CONTENT\n\n"
            HAS_BANNER=true
        fi
    done

    # SSH 배너 확인
    local SSH_BANNER=$(grep -i "^Banner" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ -n "$SSH_BANNER" ] && [ "$SSH_BANNER" != "none" ]; then
        DETAILS="${DETAILS}SSH Banner: $SSH_BANNER"
        HAS_BANNER=true
    fi

    if $HAS_BANNER; then
        RES="Y"
        DESC="로그인 경고 메시지가 설정되어 양호"
    else
        RES="N"
        DESC="로그인 경고 메시지가 설정되지 않아 취약"
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

    local SUDOERS="/etc/sudoers"

    if [ ! -f "$SUDOERS" ]; then
        RES="N/A"
        DESC="sudoers 파일이 존재하지 않아 해당 없음"
        DT="$SUDOERS: 없음"
    else
        local HAS_ISSUE=false
        local DETAILS=""

        # 파일 권한 및 소유자 확인
        local OWNER=$(stat -c "%U" "$SUDOERS" 2>/dev/null)
        local PERM=$(stat -c "%a" "$SUDOERS" 2>/dev/null)

        if [ "$OWNER" != "root" ]; then
            HAS_ISSUE=true
            DETAILS="소유자: $OWNER (취약 - root 아님)\n"
        else
            DETAILS="소유자: $OWNER (양호)\n"
        fi

        if [ "$PERM" -gt 640 ] 2>/dev/null; then
            HAS_ISSUE=true
            DETAILS="${DETAILS}권한: $PERM (취약 - 640 초과)\n"
        else
            DETAILS="${DETAILS}권한: $PERM (양호)\n"
        fi

        # NOPASSWD 또는 ALL 권한 확인
        local NOPASSWD=$(grep -v "^#" "$SUDOERS" | grep "NOPASSWD")
        local ALL_ALL=$(grep -v "^#" "$SUDOERS" | grep "ALL=(ALL)")

        DETAILS="${DETAILS}NOPASSWD 설정: $([ -n "$NOPASSWD" ] && echo '있음' || echo '없음')\n"
        DETAILS="${DETAILS}ALL 권한: $([ -n "$ALL_ALL" ] && echo '있음' || echo '없음')"

        if $HAS_ISSUE; then
            RES="N"
            DESC="sudoers 파일 권한 또는 소유자가 기준(root, 640 이하)을 충족하지 않아 취약"
        else
            # [FIX] KISA 기준 충족(소유자 root + 권한 640 이하) 시 Y(양호) 판정
            RES="Y"
            DESC="sudoers 파일 소유자가 root이고 권한이 640 이하로 설정되어 양호"
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

    local DETAILS=""

    # OS 정보
    DETAILS="OS: $SYS_OS_NAME\n"
    DETAILS="${DETAILS}Kernel: $SYS_KN\n"

    # 패키지 업데이트 확인 (yum/dnf)
    if command -v dnf &>/dev/null; then
        local UPDATES=$(dnf check-update 2>/dev/null | grep -c "^\S")
        DETAILS="${DETAILS}사용 가능한 업데이트: ${UPDATES:-확인불가}개"
    elif command -v yum &>/dev/null; then
        local UPDATES=$(yum check-update 2>/dev/null | grep -c "^\S")
        DETAILS="${DETAILS}사용 가능한 업데이트: ${UPDATES:-확인불가}개"
    fi

    RES="M"
    DESC="보안 패치 적용 현황이 수집됨, 수동 확인 필요"
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

    local RUNNING=false
    local DETAILS=""

    # chronyd 확인
    if systemctl is-active chronyd &>/dev/null; then
        RUNNING=true
        DETAILS="chronyd: 실행 중\n"
        local CHRONY_SOURCES=$(chronyc sources 2>/dev/null | head -5)
        DETAILS="${DETAILS}$CHRONY_SOURCES"
    fi

    # ntpd 확인
    if systemctl is-active ntpd &>/dev/null; then
        RUNNING=true
        DETAILS="${DETAILS}ntpd: 실행 중\n"
    fi

    # timedatectl 확인
    if command -v timedatectl &>/dev/null; then
        local SYNC_STATUS=$(timedatectl show --property=NTPSynchronized --value 2>/dev/null)
        DETAILS="${DETAILS}NTP 동기화: $SYNC_STATUS"
        [ "$SYNC_STATUS" == "yes" ] && RUNNING=true
    fi

    if $RUNNING; then
        RES="Y"
        DESC="NTP 시각 동기화가 설정되어 양호"
    else
        RES="N"
        DESC="NTP 시각 동기화가 설정되지 않아 취약"
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

    local RSYSLOG_CONF="/etc/rsyslog.conf"
    local RSYSLOG_D="/etc/rsyslog.d"
    local DETAILS=""
    local AUTHLOG=""

    if [ -f "$RSYSLOG_CONF" ]; then
        # 주요 로그 설정 확인 (rsyslog.conf)
        AUTHLOG=$(grep -E "auth\.\*|authpriv\.\*" "$RSYSLOG_CONF" | head -3)
        local MESSAGES=$(grep -E "^\*\.info|^\*\.err" "$RSYSLOG_CONF" | head -3)

        DETAILS="rsyslog.conf 설정:\n$AUTHLOG\n$MESSAGES"
    fi

    # /etc/rsyslog.d/ 디렉토리 확인
    if [ -d "$RSYSLOG_D" ]; then
        local D_AUTHLOG=$(grep -rE "auth\.\*|authpriv\.\*" "$RSYSLOG_D"/*.conf 2>/dev/null | head -3)
        if [ -n "$D_AUTHLOG" ]; then
            DETAILS="${DETAILS}\n\nrsyslog.d 설정:\n$D_AUTHLOG"
            [ -z "$AUTHLOG" ] && AUTHLOG="$D_AUTHLOG"
        fi
    fi

    if [ -n "$AUTHLOG" ]; then
        RES="Y"
        DESC="시스템 로깅(rsyslog)이 정상 설정되어 양호"
    elif systemctl is-active rsyslog &>/dev/null; then
        RES="M"
        DESC="rsyslog 서비스가 실행 중이나 로그 설정 확인됨, 수동 확인 필요"
        DETAILS="${DETAILS}\nrsyslog: 실행 중"
    else
        RES="N"
        DESC="rsyslog 서비스가 실행되지 않아 취약"
        DETAILS="rsyslog: 미실행"
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

    local LOG_DIR="/var/log"
    local VULNERABLE=""
    local DETAILS=""

    # /var/log 디렉토리 권한 확인
    local DIR_PERM=$(stat -c "%a" "$LOG_DIR" 2>/dev/null)
    local DIR_OWNER=$(stat -c "%U" "$LOG_DIR" 2>/dev/null)
    DETAILS="$LOG_DIR: ${DIR_OWNER}:${DIR_PERM}\n"

    # 주요 로그 파일 권한 확인
    local LOG_FILES="messages secure auth.log cron maillog"
    for log in $LOG_FILES; do
        local LOG_PATH="$LOG_DIR/$log"
        if [ -f "$LOG_PATH" ]; then
            local perm=$(stat -c "%a" "$LOG_PATH" 2>/dev/null)
            local owner=$(stat -c "%U" "$LOG_PATH" 2>/dev/null)
            DETAILS="${DETAILS}${log}: ${owner}:${perm}\n"
            # [FIX] 비트마스크 기반 권한 비교로 변경 — group/other 쓰기 비트 직접 검사
            local group_perm=$(( (perm / 10) % 10 ))
            local other_perm=$((perm % 10))
            if [ "$owner" != "root" ] || [ $((group_perm & 2)) -ne 0 ] || [ $((other_perm & 2)) -ne 0 ] 2>/dev/null; then
                VULNERABLE="${VULNERABLE}${log} "
            fi
        fi
    done

    if [ -z "$VULNERABLE" ]; then
        RES="Y"
        DESC="로그 파일 권한이 기준에 맞게 설정되어 양호"
    else
        RES="N"
        DESC="로그 파일 권한이 기준(other 쓰기 제한)을 초과하여 취약"
    fi

    DT="$DETAILS취약: ${VULNERABLE:-없음}"

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
echo "  OS: $SYS_OS_NAME"
echo "  커널: $SYS_KN"
echo "  IP: $SYS_IP"
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
echo ""
echo "  ─────────────────────────────────────────────────────────"
echo ""
echo "  점검이 완료되었습니다!"
echo "  호스트: $SYS_HOST"
echo "  결과 파일: $OUTPUT_FILE"
echo ""
