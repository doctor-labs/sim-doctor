_sim__doctor() {
    local i cur prev opts cmd
    COMPREPLY=()
    if [[ "${BASH_VERSINFO[0]}" -ge 4 ]]; then
        cur="$2"
    else
        cur="${COMP_WORDS[COMP_CWORD]}"
    fi
    prev="$3"
    cmd=""
    opts=""

    for i in "${COMP_WORDS[@]:0:COMP_CWORD}"
    do
        case "${cmd},${i}" in
            ",$1")
                cmd="sim__doctor"
                ;;
            sim__doctor,batch)
                cmd="sim__doctor__subcmd__batch"
                ;;
            sim__doctor,card)
                cmd="sim__doctor__subcmd__card"
                ;;
            sim__doctor,cards)
                cmd="sim__doctor__subcmd__cards"
                ;;
            sim__doctor,cat)
                cmd="sim__doctor__subcmd__cat"
                ;;
            sim__doctor,ci)
                cmd="sim__doctor__subcmd__ci"
                ;;
            sim__doctor,completions)
                cmd="sim__doctor__subcmd__completions"
                ;;
            sim__doctor,erase)
                cmd="sim__doctor__subcmd__erase"
                ;;
            sim__doctor,esim-cert)
                cmd="sim__doctor__subcmd__esim__subcmd__cert"
                ;;
            sim__doctor,euicc)
                cmd="sim__doctor__subcmd__euicc"
                ;;
            sim__doctor,fix)
                cmd="sim__doctor__subcmd__fix"
                ;;
            sim__doctor,fuzz)
                cmd="sim__doctor__subcmd__fuzz"
                ;;
            sim__doctor,gp)
                cmd="sim__doctor__subcmd__gp"
                ;;
            sim__doctor,help)
                cmd="sim__doctor__subcmd__help"
                ;;
            sim__doctor,install)
                cmd="sim__doctor__subcmd__install"
                ;;
            sim__doctor,keygen)
                cmd="sim__doctor__subcmd__keygen"
                ;;
            sim__doctor,mcp)
                cmd="sim__doctor__subcmd__mcp"
                ;;
            sim__doctor,modules)
                cmd="sim__doctor__subcmd__modules"
                ;;
            sim__doctor,ota-crypto)
                cmd="sim__doctor__subcmd__ota__subcmd__crypto"
                ;;
            sim__doctor,ota-expanded)
                cmd="sim__doctor__subcmd__ota__subcmd__expanded"
                ;;
            sim__doctor,profile)
                cmd="sim__doctor__subcmd__profile"
                ;;
            sim__doctor,readers)
                cmd="sim__doctor__subcmd__readers"
                ;;
            sim__doctor,rules)
                cmd="sim__doctor__subcmd__rules"
                ;;
            sim__doctor,saip)
                cmd="sim__doctor__subcmd__saip"
                ;;
            sim__doctor,scan)
                cmd="sim__doctor__subcmd__scan"
                ;;
            sim__doctor,sms)
                cmd="sim__doctor__subcmd__sms"
                ;;
            sim__doctor,trace)
                cmd="sim__doctor__subcmd__trace"
                ;;
            sim__doctor,ts48)
                cmd="sim__doctor__subcmd__ts48"
                ;;
            sim__doctor,why)
                cmd="sim__doctor__subcmd__why"
                ;;
            sim__doctor__subcmd__cards,fixture)
                cmd="sim__doctor__subcmd__cards__subcmd__fixture"
                ;;
            sim__doctor__subcmd__cards,help)
                cmd="sim__doctor__subcmd__cards__subcmd__help"
                ;;
            sim__doctor__subcmd__cards,list)
                cmd="sim__doctor__subcmd__cards__subcmd__list"
                ;;
            sim__doctor__subcmd__cards,show)
                cmd="sim__doctor__subcmd__cards__subcmd__show"
                ;;
            sim__doctor__subcmd__cards__subcmd__help,fixture)
                cmd="sim__doctor__subcmd__cards__subcmd__help__subcmd__fixture"
                ;;
            sim__doctor__subcmd__cards__subcmd__help,help)
                cmd="sim__doctor__subcmd__cards__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__cards__subcmd__help,list)
                cmd="sim__doctor__subcmd__cards__subcmd__help__subcmd__list"
                ;;
            sim__doctor__subcmd__cards__subcmd__help,show)
                cmd="sim__doctor__subcmd__cards__subcmd__help__subcmd__show"
                ;;
            sim__doctor__subcmd__cat,decode)
                cmd="sim__doctor__subcmd__cat__subcmd__decode"
                ;;
            sim__doctor__subcmd__cat,help)
                cmd="sim__doctor__subcmd__cat__subcmd__help"
                ;;
            sim__doctor__subcmd__cat__subcmd__help,decode)
                cmd="sim__doctor__subcmd__cat__subcmd__help__subcmd__decode"
                ;;
            sim__doctor__subcmd__cat__subcmd__help,help)
                cmd="sim__doctor__subcmd__cat__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__ci,help)
                cmd="sim__doctor__subcmd__ci__subcmd__help"
                ;;
            sim__doctor__subcmd__ci,install)
                cmd="sim__doctor__subcmd__ci__subcmd__install"
                ;;
            sim__doctor__subcmd__ci__subcmd__help,help)
                cmd="sim__doctor__subcmd__ci__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__ci__subcmd__help,install)
                cmd="sim__doctor__subcmd__ci__subcmd__help__subcmd__install"
                ;;
            sim__doctor__subcmd__esim__subcmd__cert,help)
                cmd="sim__doctor__subcmd__esim__subcmd__cert__subcmd__help"
                ;;
            sim__doctor__subcmd__esim__subcmd__cert,verify)
                cmd="sim__doctor__subcmd__esim__subcmd__cert__subcmd__verify"
                ;;
            sim__doctor__subcmd__esim__subcmd__cert__subcmd__help,help)
                cmd="sim__doctor__subcmd__esim__subcmd__cert__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__esim__subcmd__cert__subcmd__help,verify)
                cmd="sim__doctor__subcmd__esim__subcmd__cert__subcmd__help__subcmd__verify"
                ;;
            sim__doctor__subcmd__euicc,challenge)
                cmd="sim__doctor__subcmd__euicc__subcmd__challenge"
                ;;
            sim__doctor__subcmd__euicc,delete)
                cmd="sim__doctor__subcmd__euicc__subcmd__delete"
                ;;
            sim__doctor__subcmd__euicc,disable)
                cmd="sim__doctor__subcmd__euicc__subcmd__disable"
                ;;
            sim__doctor__subcmd__euicc,enable)
                cmd="sim__doctor__subcmd__euicc__subcmd__enable"
                ;;
            sim__doctor__subcmd__euicc,get-certs)
                cmd="sim__doctor__subcmd__euicc__subcmd__get__subcmd__certs"
                ;;
            sim__doctor__subcmd__euicc,get-eim-configuration-data)
                cmd="sim__doctor__subcmd__euicc__subcmd__get__subcmd__eim__subcmd__configuration__subcmd__data"
                ;;
            sim__doctor__subcmd__euicc,help)
                cmd="sim__doctor__subcmd__euicc__subcmd__help"
                ;;
            sim__doctor__subcmd__euicc,info)
                cmd="sim__doctor__subcmd__euicc__subcmd__info"
                ;;
            sim__doctor__subcmd__euicc,nickname)
                cmd="sim__doctor__subcmd__euicc__subcmd__nickname"
                ;;
            sim__doctor__subcmd__euicc,notifications)
                cmd="sim__doctor__subcmd__euicc__subcmd__notifications"
                ;;
            sim__doctor__subcmd__euicc,profiles)
                cmd="sim__doctor__subcmd__euicc__subcmd__profiles"
                ;;
            sim__doctor__subcmd__euicc,reset)
                cmd="sim__doctor__subcmd__euicc__subcmd__reset"
                ;;
            sim__doctor__subcmd__euicc,set-default-dp)
                cmd="sim__doctor__subcmd__euicc__subcmd__set__subcmd__default__subcmd__dp"
                ;;
            sim__doctor__subcmd__euicc,store-data)
                cmd="sim__doctor__subcmd__euicc__subcmd__store__subcmd__data"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help,challenge)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__challenge"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help,delete)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__delete"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help,disable)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__disable"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help,enable)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__enable"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help,get-certs)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__get__subcmd__certs"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help,get-eim-configuration-data)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__get__subcmd__eim__subcmd__configuration__subcmd__data"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help,help)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help,info)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__info"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help,nickname)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__nickname"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help,notifications)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__notifications"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help,profiles)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__profiles"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help,reset)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__reset"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help,set-default-dp)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__set__subcmd__default__subcmd__dp"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help,store-data)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__store__subcmd__data"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help__subcmd__notifications,dump)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__notifications__subcmd__dump"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help__subcmd__notifications,remove)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__notifications__subcmd__remove"
                ;;
            sim__doctor__subcmd__euicc__subcmd__help__subcmd__notifications,replay)
                cmd="sim__doctor__subcmd__euicc__subcmd__help__subcmd__notifications__subcmd__replay"
                ;;
            sim__doctor__subcmd__euicc__subcmd__notifications,dump)
                cmd="sim__doctor__subcmd__euicc__subcmd__notifications__subcmd__dump"
                ;;
            sim__doctor__subcmd__euicc__subcmd__notifications,help)
                cmd="sim__doctor__subcmd__euicc__subcmd__notifications__subcmd__help"
                ;;
            sim__doctor__subcmd__euicc__subcmd__notifications,remove)
                cmd="sim__doctor__subcmd__euicc__subcmd__notifications__subcmd__remove"
                ;;
            sim__doctor__subcmd__euicc__subcmd__notifications,replay)
                cmd="sim__doctor__subcmd__euicc__subcmd__notifications__subcmd__replay"
                ;;
            sim__doctor__subcmd__euicc__subcmd__notifications__subcmd__help,dump)
                cmd="sim__doctor__subcmd__euicc__subcmd__notifications__subcmd__help__subcmd__dump"
                ;;
            sim__doctor__subcmd__euicc__subcmd__notifications__subcmd__help,help)
                cmd="sim__doctor__subcmd__euicc__subcmd__notifications__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__euicc__subcmd__notifications__subcmd__help,remove)
                cmd="sim__doctor__subcmd__euicc__subcmd__notifications__subcmd__help__subcmd__remove"
                ;;
            sim__doctor__subcmd__euicc__subcmd__notifications__subcmd__help,replay)
                cmd="sim__doctor__subcmd__euicc__subcmd__notifications__subcmd__help__subcmd__replay"
                ;;
            sim__doctor__subcmd__fuzz,apdu)
                cmd="sim__doctor__subcmd__fuzz__subcmd__apdu"
                ;;
            sim__doctor__subcmd__fuzz,compare)
                cmd="sim__doctor__subcmd__fuzz__subcmd__compare"
                ;;
            sim__doctor__subcmd__fuzz,help)
                cmd="sim__doctor__subcmd__fuzz__subcmd__help"
                ;;
            sim__doctor__subcmd__fuzz,mutate)
                cmd="sim__doctor__subcmd__fuzz__subcmd__mutate"
                ;;
            sim__doctor__subcmd__fuzz,ota)
                cmd="sim__doctor__subcmd__fuzz__subcmd__ota"
                ;;
            sim__doctor__subcmd__fuzz__subcmd__help,apdu)
                cmd="sim__doctor__subcmd__fuzz__subcmd__help__subcmd__apdu"
                ;;
            sim__doctor__subcmd__fuzz__subcmd__help,compare)
                cmd="sim__doctor__subcmd__fuzz__subcmd__help__subcmd__compare"
                ;;
            sim__doctor__subcmd__fuzz__subcmd__help,help)
                cmd="sim__doctor__subcmd__fuzz__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__fuzz__subcmd__help,mutate)
                cmd="sim__doctor__subcmd__fuzz__subcmd__help__subcmd__mutate"
                ;;
            sim__doctor__subcmd__fuzz__subcmd__help,ota)
                cmd="sim__doctor__subcmd__fuzz__subcmd__help__subcmd__ota"
                ;;
            sim__doctor__subcmd__gp,ara)
                cmd="sim__doctor__subcmd__gp__subcmd__ara"
                ;;
            sim__doctor__subcmd__gp,aram)
                cmd="sim__doctor__subcmd__gp__subcmd__aram"
                ;;
            sim__doctor__subcmd__gp,cert)
                cmd="sim__doctor__subcmd__gp__subcmd__cert"
                ;;
            sim__doctor__subcmd__gp,channel)
                cmd="sim__doctor__subcmd__gp__subcmd__channel"
                ;;
            sim__doctor__subcmd__gp,cplc-set)
                cmd="sim__doctor__subcmd__gp__subcmd__cplc__subcmd__set"
                ;;
            sim__doctor__subcmd__gp,create-sd)
                cmd="sim__doctor__subcmd__gp__subcmd__create__subcmd__sd"
                ;;
            sim__doctor__subcmd__gp,crs)
                cmd="sim__doctor__subcmd__gp__subcmd__crs"
                ;;
            sim__doctor__subcmd__gp,delete)
                cmd="sim__doctor__subcmd__gp__subcmd__delete"
                ;;
            sim__doctor__subcmd__gp,delete-key)
                cmd="sim__doctor__subcmd__gp__subcmd__delete__subcmd__key"
                ;;
            sim__doctor__subcmd__gp,help)
                cmd="sim__doctor__subcmd__gp__subcmd__help"
                ;;
            sim__doctor__subcmd__gp,info)
                cmd="sim__doctor__subcmd__gp__subcmd__info"
                ;;
            sim__doctor__subcmd__gp,install)
                cmd="sim__doctor__subcmd__gp__subcmd__install"
                ;;
            sim__doctor__subcmd__gp,make-default)
                cmd="sim__doctor__subcmd__gp__subcmd__make__subcmd__default"
                ;;
            sim__doctor__subcmd__gp,move)
                cmd="sim__doctor__subcmd__gp__subcmd__move"
                ;;
            sim__doctor__subcmd__gp,personalize)
                cmd="sim__doctor__subcmd__gp__subcmd__personalize"
                ;;
            sim__doctor__subcmd__gp,put-key)
                cmd="sim__doctor__subcmd__gp__subcmd__put__subcmd__key"
                ;;
            sim__doctor__subcmd__gp,receipt)
                cmd="sim__doctor__subcmd__gp__subcmd__receipt"
                ;;
            sim__doctor__subcmd__gp,release-scp)
                cmd="sim__doctor__subcmd__gp__subcmd__release__subcmd__scp"
                ;;
            sim__doctor__subcmd__gp,rename-isd)
                cmd="sim__doctor__subcmd__gp__subcmd__rename__subcmd__isd"
                ;;
            sim__doctor__subcmd__gp,secure-apdu)
                cmd="sim__doctor__subcmd__gp__subcmd__secure__subcmd__apdu"
                ;;
            sim__doctor__subcmd__gp,select)
                cmd="sim__doctor__subcmd__gp__subcmd__select"
                ;;
            sim__doctor__subcmd__gp,status)
                cmd="sim__doctor__subcmd__gp__subcmd__status"
                ;;
            sim__doctor__subcmd__gp,store-data)
                cmd="sim__doctor__subcmd__gp__subcmd__store__subcmd__data"
                ;;
            sim__doctor__subcmd__gp__subcmd__aram,add)
                cmd="sim__doctor__subcmd__gp__subcmd__aram__subcmd__add"
                ;;
            sim__doctor__subcmd__gp__subcmd__aram,config)
                cmd="sim__doctor__subcmd__gp__subcmd__aram__subcmd__config"
                ;;
            sim__doctor__subcmd__gp__subcmd__aram,delete-all)
                cmd="sim__doctor__subcmd__gp__subcmd__aram__subcmd__delete__subcmd__all"
                ;;
            sim__doctor__subcmd__gp__subcmd__aram,help)
                cmd="sim__doctor__subcmd__gp__subcmd__aram__subcmd__help"
                ;;
            sim__doctor__subcmd__gp__subcmd__aram,lock)
                cmd="sim__doctor__subcmd__gp__subcmd__aram__subcmd__lock"
                ;;
            sim__doctor__subcmd__gp__subcmd__aram__subcmd__help,add)
                cmd="sim__doctor__subcmd__gp__subcmd__aram__subcmd__help__subcmd__add"
                ;;
            sim__doctor__subcmd__gp__subcmd__aram__subcmd__help,config)
                cmd="sim__doctor__subcmd__gp__subcmd__aram__subcmd__help__subcmd__config"
                ;;
            sim__doctor__subcmd__gp__subcmd__aram__subcmd__help,delete-all)
                cmd="sim__doctor__subcmd__gp__subcmd__aram__subcmd__help__subcmd__delete__subcmd__all"
                ;;
            sim__doctor__subcmd__gp__subcmd__aram__subcmd__help,help)
                cmd="sim__doctor__subcmd__gp__subcmd__aram__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__gp__subcmd__aram__subcmd__help,lock)
                cmd="sim__doctor__subcmd__gp__subcmd__aram__subcmd__help__subcmd__lock"
                ;;
            sim__doctor__subcmd__gp__subcmd__cert,construct)
                cmd="sim__doctor__subcmd__gp__subcmd__cert__subcmd__construct"
                ;;
            sim__doctor__subcmd__gp__subcmd__cert,help)
                cmd="sim__doctor__subcmd__gp__subcmd__cert__subcmd__help"
                ;;
            sim__doctor__subcmd__gp__subcmd__cert,read)
                cmd="sim__doctor__subcmd__gp__subcmd__cert__subcmd__read"
                ;;
            sim__doctor__subcmd__gp__subcmd__cert,sign)
                cmd="sim__doctor__subcmd__gp__subcmd__cert__subcmd__sign"
                ;;
            sim__doctor__subcmd__gp__subcmd__cert__subcmd__help,construct)
                cmd="sim__doctor__subcmd__gp__subcmd__cert__subcmd__help__subcmd__construct"
                ;;
            sim__doctor__subcmd__gp__subcmd__cert__subcmd__help,help)
                cmd="sim__doctor__subcmd__gp__subcmd__cert__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__gp__subcmd__cert__subcmd__help,read)
                cmd="sim__doctor__subcmd__gp__subcmd__cert__subcmd__help__subcmd__read"
                ;;
            sim__doctor__subcmd__gp__subcmd__cert__subcmd__help,sign)
                cmd="sim__doctor__subcmd__gp__subcmd__cert__subcmd__help__subcmd__sign"
                ;;
            sim__doctor__subcmd__gp__subcmd__channel,close)
                cmd="sim__doctor__subcmd__gp__subcmd__channel__subcmd__close"
                ;;
            sim__doctor__subcmd__gp__subcmd__channel,help)
                cmd="sim__doctor__subcmd__gp__subcmd__channel__subcmd__help"
                ;;
            sim__doctor__subcmd__gp__subcmd__channel,open)
                cmd="sim__doctor__subcmd__gp__subcmd__channel__subcmd__open"
                ;;
            sim__doctor__subcmd__gp__subcmd__channel__subcmd__help,close)
                cmd="sim__doctor__subcmd__gp__subcmd__channel__subcmd__help__subcmd__close"
                ;;
            sim__doctor__subcmd__gp__subcmd__channel__subcmd__help,help)
                cmd="sim__doctor__subcmd__gp__subcmd__channel__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__gp__subcmd__channel__subcmd__help,open)
                cmd="sim__doctor__subcmd__gp__subcmd__channel__subcmd__help__subcmd__open"
                ;;
            sim__doctor__subcmd__gp__subcmd__crs,activate)
                cmd="sim__doctor__subcmd__gp__subcmd__crs__subcmd__activate"
                ;;
            sim__doctor__subcmd__gp__subcmd__crs,deactivate)
                cmd="sim__doctor__subcmd__gp__subcmd__crs__subcmd__deactivate"
                ;;
            sim__doctor__subcmd__gp__subcmd__crs,help)
                cmd="sim__doctor__subcmd__gp__subcmd__crs__subcmd__help"
                ;;
            sim__doctor__subcmd__gp__subcmd__crs,info)
                cmd="sim__doctor__subcmd__gp__subcmd__crs__subcmd__info"
                ;;
            sim__doctor__subcmd__gp__subcmd__crs,list)
                cmd="sim__doctor__subcmd__gp__subcmd__crs__subcmd__list"
                ;;
            sim__doctor__subcmd__gp__subcmd__crs__subcmd__help,activate)
                cmd="sim__doctor__subcmd__gp__subcmd__crs__subcmd__help__subcmd__activate"
                ;;
            sim__doctor__subcmd__gp__subcmd__crs__subcmd__help,deactivate)
                cmd="sim__doctor__subcmd__gp__subcmd__crs__subcmd__help__subcmd__deactivate"
                ;;
            sim__doctor__subcmd__gp__subcmd__crs__subcmd__help,help)
                cmd="sim__doctor__subcmd__gp__subcmd__crs__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__gp__subcmd__crs__subcmd__help,info)
                cmd="sim__doctor__subcmd__gp__subcmd__crs__subcmd__help__subcmd__info"
                ;;
            sim__doctor__subcmd__gp__subcmd__crs__subcmd__help,list)
                cmd="sim__doctor__subcmd__gp__subcmd__crs__subcmd__help__subcmd__list"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,ara)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__ara"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,aram)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__aram"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,cert)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__cert"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,channel)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__channel"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,cplc-set)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__cplc__subcmd__set"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,create-sd)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__create__subcmd__sd"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,crs)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__crs"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,delete)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__delete"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,delete-key)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__delete__subcmd__key"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,help)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,info)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__info"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,install)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__install"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,make-default)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__make__subcmd__default"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,move)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__move"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,personalize)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__personalize"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,put-key)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__put__subcmd__key"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,receipt)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__receipt"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,release-scp)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__release__subcmd__scp"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,rename-isd)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__rename__subcmd__isd"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,secure-apdu)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__secure__subcmd__apdu"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,select)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__select"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,status)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__status"
                ;;
            sim__doctor__subcmd__gp__subcmd__help,store-data)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__store__subcmd__data"
                ;;
            sim__doctor__subcmd__gp__subcmd__help__subcmd__aram,add)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__aram__subcmd__add"
                ;;
            sim__doctor__subcmd__gp__subcmd__help__subcmd__aram,config)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__aram__subcmd__config"
                ;;
            sim__doctor__subcmd__gp__subcmd__help__subcmd__aram,delete-all)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__aram__subcmd__delete__subcmd__all"
                ;;
            sim__doctor__subcmd__gp__subcmd__help__subcmd__aram,lock)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__aram__subcmd__lock"
                ;;
            sim__doctor__subcmd__gp__subcmd__help__subcmd__cert,construct)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__cert__subcmd__construct"
                ;;
            sim__doctor__subcmd__gp__subcmd__help__subcmd__cert,read)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__cert__subcmd__read"
                ;;
            sim__doctor__subcmd__gp__subcmd__help__subcmd__cert,sign)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__cert__subcmd__sign"
                ;;
            sim__doctor__subcmd__gp__subcmd__help__subcmd__channel,close)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__channel__subcmd__close"
                ;;
            sim__doctor__subcmd__gp__subcmd__help__subcmd__channel,open)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__channel__subcmd__open"
                ;;
            sim__doctor__subcmd__gp__subcmd__help__subcmd__crs,activate)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__crs__subcmd__activate"
                ;;
            sim__doctor__subcmd__gp__subcmd__help__subcmd__crs,deactivate)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__crs__subcmd__deactivate"
                ;;
            sim__doctor__subcmd__gp__subcmd__help__subcmd__crs,info)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__crs__subcmd__info"
                ;;
            sim__doctor__subcmd__gp__subcmd__help__subcmd__crs,list)
                cmd="sim__doctor__subcmd__gp__subcmd__help__subcmd__crs__subcmd__list"
                ;;
            sim__doctor__subcmd__help,batch)
                cmd="sim__doctor__subcmd__help__subcmd__batch"
                ;;
            sim__doctor__subcmd__help,card)
                cmd="sim__doctor__subcmd__help__subcmd__card"
                ;;
            sim__doctor__subcmd__help,cards)
                cmd="sim__doctor__subcmd__help__subcmd__cards"
                ;;
            sim__doctor__subcmd__help,cat)
                cmd="sim__doctor__subcmd__help__subcmd__cat"
                ;;
            sim__doctor__subcmd__help,ci)
                cmd="sim__doctor__subcmd__help__subcmd__ci"
                ;;
            sim__doctor__subcmd__help,completions)
                cmd="sim__doctor__subcmd__help__subcmd__completions"
                ;;
            sim__doctor__subcmd__help,erase)
                cmd="sim__doctor__subcmd__help__subcmd__erase"
                ;;
            sim__doctor__subcmd__help,esim-cert)
                cmd="sim__doctor__subcmd__help__subcmd__esim__subcmd__cert"
                ;;
            sim__doctor__subcmd__help,euicc)
                cmd="sim__doctor__subcmd__help__subcmd__euicc"
                ;;
            sim__doctor__subcmd__help,fix)
                cmd="sim__doctor__subcmd__help__subcmd__fix"
                ;;
            sim__doctor__subcmd__help,fuzz)
                cmd="sim__doctor__subcmd__help__subcmd__fuzz"
                ;;
            sim__doctor__subcmd__help,gp)
                cmd="sim__doctor__subcmd__help__subcmd__gp"
                ;;
            sim__doctor__subcmd__help,help)
                cmd="sim__doctor__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__help,install)
                cmd="sim__doctor__subcmd__help__subcmd__install"
                ;;
            sim__doctor__subcmd__help,keygen)
                cmd="sim__doctor__subcmd__help__subcmd__keygen"
                ;;
            sim__doctor__subcmd__help,mcp)
                cmd="sim__doctor__subcmd__help__subcmd__mcp"
                ;;
            sim__doctor__subcmd__help,modules)
                cmd="sim__doctor__subcmd__help__subcmd__modules"
                ;;
            sim__doctor__subcmd__help,ota-crypto)
                cmd="sim__doctor__subcmd__help__subcmd__ota__subcmd__crypto"
                ;;
            sim__doctor__subcmd__help,ota-expanded)
                cmd="sim__doctor__subcmd__help__subcmd__ota__subcmd__expanded"
                ;;
            sim__doctor__subcmd__help,profile)
                cmd="sim__doctor__subcmd__help__subcmd__profile"
                ;;
            sim__doctor__subcmd__help,readers)
                cmd="sim__doctor__subcmd__help__subcmd__readers"
                ;;
            sim__doctor__subcmd__help,rules)
                cmd="sim__doctor__subcmd__help__subcmd__rules"
                ;;
            sim__doctor__subcmd__help,saip)
                cmd="sim__doctor__subcmd__help__subcmd__saip"
                ;;
            sim__doctor__subcmd__help,scan)
                cmd="sim__doctor__subcmd__help__subcmd__scan"
                ;;
            sim__doctor__subcmd__help,sms)
                cmd="sim__doctor__subcmd__help__subcmd__sms"
                ;;
            sim__doctor__subcmd__help,trace)
                cmd="sim__doctor__subcmd__help__subcmd__trace"
                ;;
            sim__doctor__subcmd__help,ts48)
                cmd="sim__doctor__subcmd__help__subcmd__ts48"
                ;;
            sim__doctor__subcmd__help,why)
                cmd="sim__doctor__subcmd__help__subcmd__why"
                ;;
            sim__doctor__subcmd__help__subcmd__cards,fixture)
                cmd="sim__doctor__subcmd__help__subcmd__cards__subcmd__fixture"
                ;;
            sim__doctor__subcmd__help__subcmd__cards,list)
                cmd="sim__doctor__subcmd__help__subcmd__cards__subcmd__list"
                ;;
            sim__doctor__subcmd__help__subcmd__cards,show)
                cmd="sim__doctor__subcmd__help__subcmd__cards__subcmd__show"
                ;;
            sim__doctor__subcmd__help__subcmd__cat,decode)
                cmd="sim__doctor__subcmd__help__subcmd__cat__subcmd__decode"
                ;;
            sim__doctor__subcmd__help__subcmd__ci,install)
                cmd="sim__doctor__subcmd__help__subcmd__ci__subcmd__install"
                ;;
            sim__doctor__subcmd__help__subcmd__esim__subcmd__cert,verify)
                cmd="sim__doctor__subcmd__help__subcmd__esim__subcmd__cert__subcmd__verify"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc,challenge)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__challenge"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc,delete)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__delete"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc,disable)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__disable"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc,enable)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__enable"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc,get-certs)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__get__subcmd__certs"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc,get-eim-configuration-data)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__get__subcmd__eim__subcmd__configuration__subcmd__data"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc,info)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__info"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc,nickname)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__nickname"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc,notifications)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__notifications"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc,profiles)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__profiles"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc,reset)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__reset"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc,set-default-dp)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__set__subcmd__default__subcmd__dp"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc,store-data)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__store__subcmd__data"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc__subcmd__notifications,dump)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__notifications__subcmd__dump"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc__subcmd__notifications,remove)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__notifications__subcmd__remove"
                ;;
            sim__doctor__subcmd__help__subcmd__euicc__subcmd__notifications,replay)
                cmd="sim__doctor__subcmd__help__subcmd__euicc__subcmd__notifications__subcmd__replay"
                ;;
            sim__doctor__subcmd__help__subcmd__fuzz,apdu)
                cmd="sim__doctor__subcmd__help__subcmd__fuzz__subcmd__apdu"
                ;;
            sim__doctor__subcmd__help__subcmd__fuzz,compare)
                cmd="sim__doctor__subcmd__help__subcmd__fuzz__subcmd__compare"
                ;;
            sim__doctor__subcmd__help__subcmd__fuzz,mutate)
                cmd="sim__doctor__subcmd__help__subcmd__fuzz__subcmd__mutate"
                ;;
            sim__doctor__subcmd__help__subcmd__fuzz,ota)
                cmd="sim__doctor__subcmd__help__subcmd__fuzz__subcmd__ota"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,ara)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__ara"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,aram)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__aram"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,cert)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__cert"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,channel)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__channel"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,cplc-set)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__cplc__subcmd__set"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,create-sd)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__create__subcmd__sd"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,crs)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__crs"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,delete)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__delete"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,delete-key)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__delete__subcmd__key"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,info)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__info"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,install)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__install"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,make-default)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__make__subcmd__default"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,move)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__move"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,personalize)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__personalize"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,put-key)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__put__subcmd__key"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,receipt)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__receipt"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,release-scp)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__release__subcmd__scp"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,rename-isd)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__rename__subcmd__isd"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,secure-apdu)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__secure__subcmd__apdu"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,select)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__select"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,status)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__status"
                ;;
            sim__doctor__subcmd__help__subcmd__gp,store-data)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__store__subcmd__data"
                ;;
            sim__doctor__subcmd__help__subcmd__gp__subcmd__aram,add)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__aram__subcmd__add"
                ;;
            sim__doctor__subcmd__help__subcmd__gp__subcmd__aram,config)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__aram__subcmd__config"
                ;;
            sim__doctor__subcmd__help__subcmd__gp__subcmd__aram,delete-all)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__aram__subcmd__delete__subcmd__all"
                ;;
            sim__doctor__subcmd__help__subcmd__gp__subcmd__aram,lock)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__aram__subcmd__lock"
                ;;
            sim__doctor__subcmd__help__subcmd__gp__subcmd__cert,construct)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__cert__subcmd__construct"
                ;;
            sim__doctor__subcmd__help__subcmd__gp__subcmd__cert,read)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__cert__subcmd__read"
                ;;
            sim__doctor__subcmd__help__subcmd__gp__subcmd__cert,sign)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__cert__subcmd__sign"
                ;;
            sim__doctor__subcmd__help__subcmd__gp__subcmd__channel,close)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__channel__subcmd__close"
                ;;
            sim__doctor__subcmd__help__subcmd__gp__subcmd__channel,open)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__channel__subcmd__open"
                ;;
            sim__doctor__subcmd__help__subcmd__gp__subcmd__crs,activate)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__crs__subcmd__activate"
                ;;
            sim__doctor__subcmd__help__subcmd__gp__subcmd__crs,deactivate)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__crs__subcmd__deactivate"
                ;;
            sim__doctor__subcmd__help__subcmd__gp__subcmd__crs,info)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__crs__subcmd__info"
                ;;
            sim__doctor__subcmd__help__subcmd__gp__subcmd__crs,list)
                cmd="sim__doctor__subcmd__help__subcmd__gp__subcmd__crs__subcmd__list"
                ;;
            sim__doctor__subcmd__help__subcmd__ota__subcmd__crypto,check)
                cmd="sim__doctor__subcmd__help__subcmd__ota__subcmd__crypto__subcmd__check"
                ;;
            sim__doctor__subcmd__help__subcmd__ota__subcmd__crypto,decrypt)
                cmd="sim__doctor__subcmd__help__subcmd__ota__subcmd__crypto__subcmd__decrypt"
                ;;
            sim__doctor__subcmd__help__subcmd__ota__subcmd__crypto,encrypt)
                cmd="sim__doctor__subcmd__help__subcmd__ota__subcmd__crypto__subcmd__encrypt"
                ;;
            sim__doctor__subcmd__help__subcmd__ota__subcmd__crypto,sign)
                cmd="sim__doctor__subcmd__help__subcmd__ota__subcmd__crypto__subcmd__sign"
                ;;
            sim__doctor__subcmd__help__subcmd__ota__subcmd__expanded,decode)
                cmd="sim__doctor__subcmd__help__subcmd__ota__subcmd__expanded__subcmd__decode"
                ;;
            sim__doctor__subcmd__help__subcmd__ota__subcmd__expanded,encode)
                cmd="sim__doctor__subcmd__help__subcmd__ota__subcmd__expanded__subcmd__encode"
                ;;
            sim__doctor__subcmd__help__subcmd__ota__subcmd__expanded,por)
                cmd="sim__doctor__subcmd__help__subcmd__ota__subcmd__expanded__subcmd__por"
                ;;
            sim__doctor__subcmd__help__subcmd__profile,list)
                cmd="sim__doctor__subcmd__help__subcmd__profile__subcmd__list"
                ;;
            sim__doctor__subcmd__help__subcmd__profile,match)
                cmd="sim__doctor__subcmd__help__subcmd__profile__subcmd__match"
                ;;
            sim__doctor__subcmd__help__subcmd__profile,probe)
                cmd="sim__doctor__subcmd__help__subcmd__profile__subcmd__probe"
                ;;
            sim__doctor__subcmd__help__subcmd__rules,explain)
                cmd="sim__doctor__subcmd__help__subcmd__rules__subcmd__explain"
                ;;
            sim__doctor__subcmd__help__subcmd__rules,list)
                cmd="sim__doctor__subcmd__help__subcmd__rules__subcmd__list"
                ;;
            sim__doctor__subcmd__help__subcmd__saip,parse)
                cmd="sim__doctor__subcmd__help__subcmd__saip__subcmd__parse"
                ;;
            sim__doctor__subcmd__help__subcmd__sms,decode)
                cmd="sim__doctor__subcmd__help__subcmd__sms__subcmd__decode"
                ;;
            sim__doctor__subcmd__help__subcmd__ts48,compare)
                cmd="sim__doctor__subcmd__help__subcmd__ts48__subcmd__compare"
                ;;
            sim__doctor__subcmd__ota__subcmd__crypto,check)
                cmd="sim__doctor__subcmd__ota__subcmd__crypto__subcmd__check"
                ;;
            sim__doctor__subcmd__ota__subcmd__crypto,decrypt)
                cmd="sim__doctor__subcmd__ota__subcmd__crypto__subcmd__decrypt"
                ;;
            sim__doctor__subcmd__ota__subcmd__crypto,encrypt)
                cmd="sim__doctor__subcmd__ota__subcmd__crypto__subcmd__encrypt"
                ;;
            sim__doctor__subcmd__ota__subcmd__crypto,help)
                cmd="sim__doctor__subcmd__ota__subcmd__crypto__subcmd__help"
                ;;
            sim__doctor__subcmd__ota__subcmd__crypto,sign)
                cmd="sim__doctor__subcmd__ota__subcmd__crypto__subcmd__sign"
                ;;
            sim__doctor__subcmd__ota__subcmd__crypto__subcmd__help,check)
                cmd="sim__doctor__subcmd__ota__subcmd__crypto__subcmd__help__subcmd__check"
                ;;
            sim__doctor__subcmd__ota__subcmd__crypto__subcmd__help,decrypt)
                cmd="sim__doctor__subcmd__ota__subcmd__crypto__subcmd__help__subcmd__decrypt"
                ;;
            sim__doctor__subcmd__ota__subcmd__crypto__subcmd__help,encrypt)
                cmd="sim__doctor__subcmd__ota__subcmd__crypto__subcmd__help__subcmd__encrypt"
                ;;
            sim__doctor__subcmd__ota__subcmd__crypto__subcmd__help,help)
                cmd="sim__doctor__subcmd__ota__subcmd__crypto__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__ota__subcmd__crypto__subcmd__help,sign)
                cmd="sim__doctor__subcmd__ota__subcmd__crypto__subcmd__help__subcmd__sign"
                ;;
            sim__doctor__subcmd__ota__subcmd__expanded,decode)
                cmd="sim__doctor__subcmd__ota__subcmd__expanded__subcmd__decode"
                ;;
            sim__doctor__subcmd__ota__subcmd__expanded,encode)
                cmd="sim__doctor__subcmd__ota__subcmd__expanded__subcmd__encode"
                ;;
            sim__doctor__subcmd__ota__subcmd__expanded,help)
                cmd="sim__doctor__subcmd__ota__subcmd__expanded__subcmd__help"
                ;;
            sim__doctor__subcmd__ota__subcmd__expanded,por)
                cmd="sim__doctor__subcmd__ota__subcmd__expanded__subcmd__por"
                ;;
            sim__doctor__subcmd__ota__subcmd__expanded__subcmd__help,decode)
                cmd="sim__doctor__subcmd__ota__subcmd__expanded__subcmd__help__subcmd__decode"
                ;;
            sim__doctor__subcmd__ota__subcmd__expanded__subcmd__help,encode)
                cmd="sim__doctor__subcmd__ota__subcmd__expanded__subcmd__help__subcmd__encode"
                ;;
            sim__doctor__subcmd__ota__subcmd__expanded__subcmd__help,help)
                cmd="sim__doctor__subcmd__ota__subcmd__expanded__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__ota__subcmd__expanded__subcmd__help,por)
                cmd="sim__doctor__subcmd__ota__subcmd__expanded__subcmd__help__subcmd__por"
                ;;
            sim__doctor__subcmd__profile,help)
                cmd="sim__doctor__subcmd__profile__subcmd__help"
                ;;
            sim__doctor__subcmd__profile,list)
                cmd="sim__doctor__subcmd__profile__subcmd__list"
                ;;
            sim__doctor__subcmd__profile,match)
                cmd="sim__doctor__subcmd__profile__subcmd__match"
                ;;
            sim__doctor__subcmd__profile,probe)
                cmd="sim__doctor__subcmd__profile__subcmd__probe"
                ;;
            sim__doctor__subcmd__profile__subcmd__help,help)
                cmd="sim__doctor__subcmd__profile__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__profile__subcmd__help,list)
                cmd="sim__doctor__subcmd__profile__subcmd__help__subcmd__list"
                ;;
            sim__doctor__subcmd__profile__subcmd__help,match)
                cmd="sim__doctor__subcmd__profile__subcmd__help__subcmd__match"
                ;;
            sim__doctor__subcmd__profile__subcmd__help,probe)
                cmd="sim__doctor__subcmd__profile__subcmd__help__subcmd__probe"
                ;;
            sim__doctor__subcmd__rules,explain)
                cmd="sim__doctor__subcmd__rules__subcmd__explain"
                ;;
            sim__doctor__subcmd__rules,help)
                cmd="sim__doctor__subcmd__rules__subcmd__help"
                ;;
            sim__doctor__subcmd__rules,list)
                cmd="sim__doctor__subcmd__rules__subcmd__list"
                ;;
            sim__doctor__subcmd__rules__subcmd__help,explain)
                cmd="sim__doctor__subcmd__rules__subcmd__help__subcmd__explain"
                ;;
            sim__doctor__subcmd__rules__subcmd__help,help)
                cmd="sim__doctor__subcmd__rules__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__rules__subcmd__help,list)
                cmd="sim__doctor__subcmd__rules__subcmd__help__subcmd__list"
                ;;
            sim__doctor__subcmd__saip,help)
                cmd="sim__doctor__subcmd__saip__subcmd__help"
                ;;
            sim__doctor__subcmd__saip,parse)
                cmd="sim__doctor__subcmd__saip__subcmd__parse"
                ;;
            sim__doctor__subcmd__saip__subcmd__help,help)
                cmd="sim__doctor__subcmd__saip__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__saip__subcmd__help,parse)
                cmd="sim__doctor__subcmd__saip__subcmd__help__subcmd__parse"
                ;;
            sim__doctor__subcmd__sms,decode)
                cmd="sim__doctor__subcmd__sms__subcmd__decode"
                ;;
            sim__doctor__subcmd__sms,help)
                cmd="sim__doctor__subcmd__sms__subcmd__help"
                ;;
            sim__doctor__subcmd__sms__subcmd__help,decode)
                cmd="sim__doctor__subcmd__sms__subcmd__help__subcmd__decode"
                ;;
            sim__doctor__subcmd__sms__subcmd__help,help)
                cmd="sim__doctor__subcmd__sms__subcmd__help__subcmd__help"
                ;;
            sim__doctor__subcmd__ts48,compare)
                cmd="sim__doctor__subcmd__ts48__subcmd__compare"
                ;;
            sim__doctor__subcmd__ts48,help)
                cmd="sim__doctor__subcmd__ts48__subcmd__help"
                ;;
            sim__doctor__subcmd__ts48__subcmd__help,compare)
                cmd="sim__doctor__subcmd__ts48__subcmd__help__subcmd__compare"
                ;;
            sim__doctor__subcmd__ts48__subcmd__help,help)
                cmd="sim__doctor__subcmd__ts48__subcmd__help__subcmd__help"
                ;;
            *)
                ;;
        esac
    done

    case "${cmd}" in
        sim__doctor)
            opts="-h -V --help --version modules readers scan profile cards ts48 batch install ci completions mcp rules why fix gp trace cat sms saip ota-crypto esim-cert ota-expanded keygen fuzz euicc card erase help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 1 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__batch)
            opts="-X -h --exclusive --plan --state --reader --yes --on-failure --retry-failed --batch-name --handler --chv-file --chv-env --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --plan)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --state)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --on-failure)
                    COMPREPLY=($(compgen -W "stop continue" -- "${cur}"))
                    return 0
                    ;;
                --batch-name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --handler)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --chv-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --chv-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__card)
            opts="-c -X -h --reader --profile --dialect --script --read-csv --write-csv --json --chv-file --chv-env --key-file --exclusive --card-key-csv --card-key-key --card-key-key-env --yes --dump --force --dump-secrets --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -W "uicc sim" -- "${cur}"))
                    return 0
                    ;;
                --dialect)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --script)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --read-csv)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --write-csv)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --chv-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --chv-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --card-key-csv)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --card-key-key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --card-key-key-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dump)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__cards)
            opts="-h --help list show fixture help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__cards__subcmd__fixture)
            opts="-h --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__cards__subcmd__help)
            opts="list show fixture help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__cards__subcmd__help__subcmd__fixture)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__cards__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__cards__subcmd__help__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__cards__subcmd__help__subcmd__show)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__cards__subcmd__list)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__cards__subcmd__show)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__cat)
            opts="-h --help decode help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__cat__subcmd__decode)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__cat__subcmd__help)
            opts="decode help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__cat__subcmd__help__subcmd__decode)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__cat__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ci)
            opts="-h --help install help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ci__subcmd__help)
            opts="install help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ci__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ci__subcmd__help__subcmd__install)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ci__subcmd__install)
            opts="-h --swsim --baseline --require-baseline --severity --ref --dir --force --print-only --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --swsim)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --require-baseline)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --severity)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --ref)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__completions)
            opts="-h --help bash elvish fish powershell zsh"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__erase)
            opts="-X -h --exclusive --class --records --dry-run --confirm-iccid --yes --reader --json --keys-file --keys-env --key-version --mode --key-kdf --s16 --channel --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --class)
                    COMPREPLY=($(compgen -W "magicsim supersim fakemagicsim" -- "${cur}"))
                    return 0
                    ;;
                --records)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --confirm-iccid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mode)
                    COMPREPLY=($(compgen -W "mac enc rmac renc all" -- "${cur}"))
                    return 0
                    ;;
                --key-kdf)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__esim__subcmd__cert)
            opts="-h --help verify help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__esim__subcmd__cert__subcmd__help)
            opts="verify help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__esim__subcmd__cert__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__esim__subcmd__cert__subcmd__help__subcmd__verify)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__esim__subcmd__cert__subcmd__verify)
            opts="-h --root --at --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --at)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc)
            opts="-h --help info profiles challenge get-certs get-eim-configuration-data notifications nickname enable disable delete reset set-default-dp store-data help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__challenge)
            opts="-h --reader --json --aid --max-segment --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-segment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__delete)
            opts="-h --yes --reader --json --aid --max-segment --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-segment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__disable)
            opts="-h --yes --reader --json --aid --max-segment --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-segment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__enable)
            opts="-h --yes --reader --json --aid --max-segment --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-segment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__get__subcmd__certs)
            opts="-h --reader --json --aid --max-segment --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-segment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__get__subcmd__eim__subcmd__configuration__subcmd__data)
            opts="-h --reader --json --aid --max-segment --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-segment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help)
            opts="info profiles challenge get-certs get-eim-configuration-data notifications nickname enable disable delete reset set-default-dp store-data help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__challenge)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__disable)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__enable)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__get__subcmd__certs)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__get__subcmd__eim__subcmd__configuration__subcmd__data)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__info)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__nickname)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__notifications)
            opts="remove dump replay"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__notifications__subcmd__dump)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__notifications__subcmd__remove)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__notifications__subcmd__replay)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__profiles)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__reset)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__set__subcmd__default__subcmd__dp)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__help__subcmd__store__subcmd__data)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__info)
            opts="-h --reader --json --aid --max-segment --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-segment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__nickname)
            opts="-h --yes --reader --json --aid --max-segment --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-segment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__notifications)
            opts="-h --reader --json --aid --max-segment --help remove dump replay help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-segment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__notifications__subcmd__dump)
            opts="-o -h --seq --output --reader --json --aid --max-segment --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --seq)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -o)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-segment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__notifications__subcmd__help)
            opts="remove dump replay help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__notifications__subcmd__help__subcmd__dump)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__notifications__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__notifications__subcmd__help__subcmd__remove)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__notifications__subcmd__help__subcmd__replay)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__notifications__subcmd__remove)
            opts="-h --yes --reader --json --aid --max-segment --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-segment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__notifications__subcmd__replay)
            opts="-h --from --yes --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__profiles)
            opts="-h --reader --json --aid --max-segment --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-segment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__reset)
            opts="-h --operational --test --smdp-address --confirm-eid --yes --reader --json --aid --max-segment --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --confirm-eid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-segment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__set__subcmd__default__subcmd__dp)
            opts="-h --yes --reader --json --aid --max-segment --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-segment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__euicc__subcmd__store__subcmd__data)
            opts="-h --yes --reader --json --aid --max-segment --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-segment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__fix)
            opts="-h --from --agent --skip-approvals --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --agent)
                    COMPREPLY=($(compgen -W "claude codex cursor" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__fuzz)
            opts="-h --help apdu ota mutate compare help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__fuzz__subcmd__apdu)
            opts="-h --i-understand-this-can-brick-the-card --allow-real-hardware --reader --json --quick --level --class --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --level)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --class)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__fuzz__subcmd__compare)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__fuzz__subcmd__help)
            opts="apdu ota mutate compare help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__fuzz__subcmd__help__subcmd__apdu)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__fuzz__subcmd__help__subcmd__compare)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__fuzz__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__fuzz__subcmd__help__subcmd__mutate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__fuzz__subcmd__help__subcmd__ota)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__fuzz__subcmd__mutate)
            opts="-h --replay --mock --max-cases --timeout --seed --dry-run --stop-on-first-finding --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --replay)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-cases)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --seed)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__fuzz__subcmd__ota)
            opts="-h --i-understand-this-can-brick-the-card --allow-real-hardware --reader --json --quick --poke --kic --kid --spi1 --spi2 --class --passthrough --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --kic)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --kid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --spi1)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --spi2)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --class)
                    COMPREPLY=($(compgen -W "etsi gsm" -- "${cur}"))
                    return 0
                    ;;
                --passthrough)
                    COMPREPLY=($(compgen -W "default bruteforce" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp)
            opts="-P -h --profile --help cert info ara status select crs channel release-scp delete make-default rename-isd delete-key install create-sd put-key cplc-set personalize aram move receipt store-data secure-apdu help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__ara)
            opts="-P -h --reader --json --trace --channel --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__aram)
            opts="-P -h --profile --help add delete-all lock config help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__aram__subcmd__add)
            opts="-P -h --aid --aid-empty --device-app-id --pkg-ref --apdu-never --apdu-always --apdu-filter --nfc-never --nfc-always --android-permissions --reader --json --trace --keys-file --keys-env --key-version --mode --key-kdf --s16 --channel --yes --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --device-app-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pkg-ref)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --apdu-filter)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --android-permissions)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mode)
                    COMPREPLY=($(compgen -W "mac enc rmac renc all" -- "${cur}"))
                    return 0
                    ;;
                --key-kdf)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__aram__subcmd__config)
            opts="-P -h --major --minor --patch --reader --json --trace --keys-file --keys-env --key-version --mode --key-kdf --s16 --channel --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --major)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --minor)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --patch)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mode)
                    COMPREPLY=($(compgen -W "mac enc rmac renc all" -- "${cur}"))
                    return 0
                    ;;
                --key-kdf)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__aram__subcmd__delete__subcmd__all)
            opts="-P -h --confirm-delete-all --reader --json --trace --keys-file --keys-env --key-version --mode --key-kdf --s16 --channel --yes --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --confirm-delete-all)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mode)
                    COMPREPLY=($(compgen -W "mac enc rmac renc all" -- "${cur}"))
                    return 0
                    ;;
                --key-kdf)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__aram__subcmd__help)
            opts="add delete-all lock config help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__aram__subcmd__help__subcmd__add)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__aram__subcmd__help__subcmd__config)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__aram__subcmd__help__subcmd__delete__subcmd__all)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__aram__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__aram__subcmd__help__subcmd__lock)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__aram__subcmd__lock)
            opts="-P -h --reader --json --trace --keys-file --keys-env --key-version --mode --key-kdf --s16 --channel --yes --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mode)
                    COMPREPLY=($(compgen -W "mac enc rmac renc all" -- "${cur}"))
                    return 0
                    ;;
                --key-kdf)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__cert)
            opts="-P -h --profile --help read construct sign help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__cert__subcmd__construct)
            opts="-P -h --cert-serial --cert-ca --cert-subject --cert-usage --cert-effective --cert-expires --cert-image-number --cert-discretionary --cert-authorizations --cert-pubkey --cert-out --json --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert-serial)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-ca)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-subject)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-usage)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-effective)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-expires)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-image-number)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-discretionary)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-authorizations)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-pubkey)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-out)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__cert__subcmd__help)
            opts="read construct sign help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__cert__subcmd__help__subcmd__construct)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__cert__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__cert__subcmd__help__subcmd__read)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__cert__subcmd__help__subcmd__sign)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__cert__subcmd__read)
            opts="-P -h --reader --json --trace --channel --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__cert__subcmd__sign)
            opts="-P -h --cert-serial --cert-ca --cert-subject --cert-usage --cert-effective --cert-expires --cert-image-number --cert-discretionary --cert-authorizations --cert-pubkey --cert-out --cert-key-file --cert-key-env --json --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert-serial)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-ca)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-subject)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-usage)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-effective)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-expires)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-image-number)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-discretionary)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-authorizations)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-pubkey)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-out)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-key-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-key-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__channel)
            opts="-P -h --profile --help open close help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__channel__subcmd__close)
            opts="-P -h --channel --reader --json --trace --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__channel__subcmd__help)
            opts="open close help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__channel__subcmd__help__subcmd__close)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__channel__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__channel__subcmd__help__subcmd__open)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__channel__subcmd__open)
            opts="-P -h --reader --json --trace --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__cplc__subcmd__set)
            opts="-P -h --kind --data --today --reader --json --trace --keys-file --keys-env --key-version --mode --key-kdf --s16 --channel --yes --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --kind)
                    COMPREPLY=($(compgen -W "pre-perso perso" -- "${cur}"))
                    return 0
                    ;;
                --data)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mode)
                    COMPREPLY=($(compgen -W "mac enc rmac renc all" -- "${cur}"))
                    return 0
                    ;;
                --key-kdf)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__create__subcmd__sd)
            opts="-P -h --domain --privileges --allow-to --allow-from --scp --params --reader --json --trace --keys-file --keys-env --key-version --mode --key-kdf --s16 --channel --yes --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --domain)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --privileges)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --scp)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --params)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mode)
                    COMPREPLY=($(compgen -W "mac enc rmac renc all" -- "${cur}"))
                    return 0
                    ;;
                --key-kdf)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__crs)
            opts="-P -h --profile --help list info activate deactivate help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__crs__subcmd__activate)
            opts="-P -h --reader --json --trace --keys-file --keys-env --key-version --mode --key-kdf --s16 --channel --yes --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mode)
                    COMPREPLY=($(compgen -W "mac enc rmac renc all" -- "${cur}"))
                    return 0
                    ;;
                --key-kdf)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__crs__subcmd__deactivate)
            opts="-P -h --reader --json --trace --keys-file --keys-env --key-version --mode --key-kdf --s16 --channel --yes --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mode)
                    COMPREPLY=($(compgen -W "mac enc rmac renc all" -- "${cur}"))
                    return 0
                    ;;
                --key-kdf)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__crs__subcmd__help)
            opts="list info activate deactivate help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__crs__subcmd__help__subcmd__activate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__crs__subcmd__help__subcmd__deactivate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__crs__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__crs__subcmd__help__subcmd__info)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__crs__subcmd__help__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__crs__subcmd__info)
            opts="-P -h --reader --json --trace --channel --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__crs__subcmd__list)
            opts="-P -h --aid --reader --json --trace --channel --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__delete)
            opts="-P -h --aid --related --dm-key-file --dm-key-env --dm-token-file --dm-token-env --reader --json --trace --keys-file --keys-env --key-version --mode --key-kdf --s16 --channel --yes --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dm-key-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dm-key-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dm-token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dm-token-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mode)
                    COMPREPLY=($(compgen -W "mac enc rmac renc all" -- "${cur}"))
                    return 0
                    ;;
                --key-kdf)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__delete__subcmd__key)
            opts="-P -h --key-id --key-version --related --allow-lockout --reader --json --trace --channel --keys-file --keys-env --yes --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --key-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help)
            opts="cert info ara status select crs channel release-scp delete make-default rename-isd delete-key install create-sd put-key cplc-set personalize aram move receipt store-data secure-apdu help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__ara)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__aram)
            opts="add delete-all lock config"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__aram__subcmd__add)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__aram__subcmd__config)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__aram__subcmd__delete__subcmd__all)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__aram__subcmd__lock)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__cert)
            opts="read construct sign"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__cert__subcmd__construct)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__cert__subcmd__read)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__cert__subcmd__sign)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__channel)
            opts="open close"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__channel__subcmd__close)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__channel__subcmd__open)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__cplc__subcmd__set)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__create__subcmd__sd)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__crs)
            opts="list info activate deactivate"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__crs__subcmd__activate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__crs__subcmd__deactivate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__crs__subcmd__info)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__crs__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__delete__subcmd__key)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__info)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__install)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__make__subcmd__default)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__move)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__personalize)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__put__subcmd__key)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__receipt)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__release__subcmd__scp)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__rename__subcmd__isd)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__secure__subcmd__apdu)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__select)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__help__subcmd__store__subcmd__data)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__info)
            opts="-P -h --reader --json --trace --channel --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__install)
            opts="-F -P -h --load --install-only --update --package --module --app --params --no-felix --privileges --make-default --bs --cl-activated --cl-notify --cl-notify-remove --cl-family --cl-display-optional --cl-contact --cl-contactless --dap-key-file --dap-key-env --dap-domain --dap-alg --dap-hash --dm-key-file --dm-key-env --dm-token-file --dm-token-env --reader --json --trace --keys-file --keys-env --key-version --mode --key-kdf --s16 --channel --yes --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --load)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --update)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --package)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --module)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --app)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --params)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --privileges)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --bs)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cl-notify)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cl-notify-remove)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cl-family)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dap-key-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dap-key-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dap-domain)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dap-alg)
                    COMPREPLY=($(compgen -W "aes des ecc" -- "${cur}"))
                    return 0
                    ;;
                --dap-hash)
                    COMPREPLY=($(compgen -W "sha256 sha384 sha512" -- "${cur}"))
                    return 0
                    ;;
                --dm-key-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dm-key-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dm-token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dm-token-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mode)
                    COMPREPLY=($(compgen -W "mac enc rmac renc all" -- "${cur}"))
                    return 0
                    ;;
                --key-kdf)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__make__subcmd__default)
            opts="-P -h --aid --reader --json --trace --keys-file --keys-env --key-version --mode --key-kdf --s16 --channel --yes --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mode)
                    COMPREPLY=($(compgen -W "mac enc rmac renc all" -- "${cur}"))
                    return 0
                    ;;
                --key-kdf)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__move)
            opts="-P -h --aid --from --to --reader --json --trace --keys-file --keys-env --key-version --mode --key-kdf --s16 --channel --yes --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --to)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mode)
                    COMPREPLY=($(compgen -W "mac enc rmac renc all" -- "${cur}"))
                    return 0
                    ;;
                --key-kdf)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__personalize)
            opts="-P -h --aid --data --reader --json --trace --keys-file --keys-env --key-version --mode --key-kdf --s16 --channel --yes --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --data)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mode)
                    COMPREPLY=($(compgen -W "mac enc rmac renc all" -- "${cur}"))
                    return 0
                    ;;
                --key-kdf)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__put__subcmd__key)
            opts="-P -h --new-key-version --replace-key-version --key-id --new-keys-file --new-keys-env --replace-current-keyset --reader --json --trace --keys-file --keys-env --key-version --mode --key-kdf --s16 --channel --yes --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --new-key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --replace-key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --new-keys-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --new-keys-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mode)
                    COMPREPLY=($(compgen -W "mac enc rmac renc all" -- "${cur}"))
                    return 0
                    ;;
                --key-kdf)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__receipt)
            opts="-P -h --receipt --response --confirmation-data --kind --elf-aid --sd-aid --app-aid --from-aid --to-aid --privileges --registry-params --receipt-key-file --receipt-key-env --json --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --receipt)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --response)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --confirmation-data)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --kind)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --elf-aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sd-aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --app-aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --from-aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --to-aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --privileges)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --registry-params)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --receipt-key-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --receipt-key-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__release__subcmd__scp)
            opts="-P -h --channel --reader --json --trace --yes --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__rename__subcmd__isd)
            opts="-P -h --new-aid --reader --json --trace --keys-file --keys-env --key-version --mode --key-kdf --s16 --channel --yes --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --new-aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mode)
                    COMPREPLY=($(compgen -W "mac enc rmac renc all" -- "${cur}"))
                    return 0
                    ;;
                --key-kdf)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__secure__subcmd__apdu)
            opts="-P -h --reader --json --trace --keys-file --keys-env --key-version --mode --key-kdf --s16 --channel --yes --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mode)
                    COMPREPLY=($(compgen -W "mac enc rmac renc all" -- "${cur}"))
                    return 0
                    ;;
                --key-kdf)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__select)
            opts="-P -h --aid --reader --json --trace --channel --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --aid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__status)
            opts="-P -h --reader --json --list --info --trace --channel --keys-file --keys-env --key-version --mode --key-kdf --s16 --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mode)
                    COMPREPLY=($(compgen -W "mac enc rmac renc all" -- "${cur}"))
                    return 0
                    ;;
                --key-kdf)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__gp__subcmd__store__subcmd__data)
            opts="-P -h --data --dgi-tag --dgi-value --emv-perso --emv-pre-perso --structure --encryption --response --block-size --reader --json --trace --keys-file --keys-env --key-version --mode --key-kdf --s16 --channel --yes --profile --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --data)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dgi-tag)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dgi-value)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --emv-perso)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --emv-pre-perso)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --structure)
                    COMPREPLY=($(compgen -W "none dgi ber-tlv" -- "${cur}"))
                    return 0
                    ;;
                --encryption)
                    COMPREPLY=($(compgen -W "none app encrypted" -- "${cur}"))
                    return 0
                    ;;
                --block-size)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mode)
                    COMPREPLY=($(compgen -W "mac enc rmac renc all" -- "${cur}"))
                    return 0
                    ;;
                --key-kdf)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --channel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -P)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help)
            opts="modules readers scan profile cards ts48 batch install ci completions mcp rules why fix gp trace cat sms saip ota-crypto esim-cert ota-expanded keygen fuzz euicc card erase help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__batch)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__card)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__cards)
            opts="list show fixture"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__cards__subcmd__fixture)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__cards__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__cards__subcmd__show)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__cat)
            opts="decode"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__cat__subcmd__decode)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__ci)
            opts="install"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__ci__subcmd__install)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__completions)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__erase)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__esim__subcmd__cert)
            opts="verify"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__esim__subcmd__cert__subcmd__verify)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc)
            opts="info profiles challenge get-certs get-eim-configuration-data notifications nickname enable disable delete reset set-default-dp store-data"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__challenge)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__disable)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__enable)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__get__subcmd__certs)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__get__subcmd__eim__subcmd__configuration__subcmd__data)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__info)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__nickname)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__notifications)
            opts="remove dump replay"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__notifications__subcmd__dump)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__notifications__subcmd__remove)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__notifications__subcmd__replay)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__profiles)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__reset)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__set__subcmd__default__subcmd__dp)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__euicc__subcmd__store__subcmd__data)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__fix)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__fuzz)
            opts="apdu ota mutate compare"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__fuzz__subcmd__apdu)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__fuzz__subcmd__compare)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__fuzz__subcmd__mutate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__fuzz__subcmd__ota)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp)
            opts="cert info ara status select crs channel release-scp delete make-default rename-isd delete-key install create-sd put-key cplc-set personalize aram move receipt store-data secure-apdu"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__ara)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__aram)
            opts="add delete-all lock config"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__aram__subcmd__add)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__aram__subcmd__config)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__aram__subcmd__delete__subcmd__all)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__aram__subcmd__lock)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__cert)
            opts="read construct sign"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__cert__subcmd__construct)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__cert__subcmd__read)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__cert__subcmd__sign)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__channel)
            opts="open close"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__channel__subcmd__close)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__channel__subcmd__open)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__cplc__subcmd__set)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__create__subcmd__sd)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__crs)
            opts="list info activate deactivate"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__crs__subcmd__activate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__crs__subcmd__deactivate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__crs__subcmd__info)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__crs__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__delete__subcmd__key)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__info)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__install)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__make__subcmd__default)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__move)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__personalize)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__put__subcmd__key)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__receipt)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__release__subcmd__scp)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__rename__subcmd__isd)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__secure__subcmd__apdu)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__select)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__gp__subcmd__store__subcmd__data)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__install)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__keygen)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__mcp)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__modules)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__ota__subcmd__crypto)
            opts="encrypt decrypt sign check"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__ota__subcmd__crypto__subcmd__check)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__ota__subcmd__crypto__subcmd__decrypt)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__ota__subcmd__crypto__subcmd__encrypt)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__ota__subcmd__crypto__subcmd__sign)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__ota__subcmd__expanded)
            opts="encode decode por"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__ota__subcmd__expanded__subcmd__decode)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__ota__subcmd__expanded__subcmd__encode)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__ota__subcmd__expanded__subcmd__por)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__profile)
            opts="list probe match"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__profile__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__profile__subcmd__match)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__profile__subcmd__probe)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__readers)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__rules)
            opts="list explain"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__rules__subcmd__explain)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__rules__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__saip)
            opts="parse"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__saip__subcmd__parse)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__scan)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__sms)
            opts="decode"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__sms__subcmd__decode)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__trace)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__ts48)
            opts="compare"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__ts48__subcmd__compare)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__help__subcmd__why)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__install)
            opts="-h --agent --print-only --dir --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --agent)
                    COMPREPLY=($(compgen -W "claude cursor codex opencode" -- "${cur}"))
                    return 0
                    ;;
                --dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__keygen)
            opts="-z -j -h --secret-file --secret-env --index --salt --mcc --mnc --mnclen --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --secret-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -z)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --secret-env)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --index)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -j)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --salt)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mcc)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mnc)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mnclen)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__mcp)
            opts="-h --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__modules)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ota__subcmd__crypto)
            opts="-h --help encrypt decrypt sign check help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ota__subcmd__crypto__subcmd__check)
            opts="-h --alg --key --mac --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --alg)
                    COMPREPLY=($(compgen -W "des 3des aes" -- "${cur}"))
                    return 0
                    ;;
                --key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mac)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ota__subcmd__crypto__subcmd__decrypt)
            opts="-h --alg --key --iv --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --alg)
                    COMPREPLY=($(compgen -W "des 3des aes" -- "${cur}"))
                    return 0
                    ;;
                --key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --iv)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ota__subcmd__crypto__subcmd__encrypt)
            opts="-h --alg --key --iv --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --alg)
                    COMPREPLY=($(compgen -W "des 3des aes" -- "${cur}"))
                    return 0
                    ;;
                --key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --iv)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ota__subcmd__crypto__subcmd__help)
            opts="encrypt decrypt sign check help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ota__subcmd__crypto__subcmd__help__subcmd__check)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ota__subcmd__crypto__subcmd__help__subcmd__decrypt)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ota__subcmd__crypto__subcmd__help__subcmd__encrypt)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ota__subcmd__crypto__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ota__subcmd__crypto__subcmd__help__subcmd__sign)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ota__subcmd__crypto__subcmd__sign)
            opts="-h --alg --key --mac-len --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --alg)
                    COMPREPLY=($(compgen -W "des 3des aes" -- "${cur}"))
                    return 0
                    ;;
                --key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mac-len)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ota__subcmd__expanded)
            opts="-h --help encode decode por help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ota__subcmd__expanded__subcmd__decode)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ota__subcmd__expanded__subcmd__encode)
            opts="-h --indefinite --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ota__subcmd__expanded__subcmd__help)
            opts="encode decode por help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ota__subcmd__expanded__subcmd__help__subcmd__decode)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ota__subcmd__expanded__subcmd__help__subcmd__encode)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ota__subcmd__expanded__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ota__subcmd__expanded__subcmd__help__subcmd__por)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ota__subcmd__expanded__subcmd__por)
            opts="-h --remote-format --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --remote-format)
                    COMPREPLY=($(compgen -W "compact expanded" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__profile)
            opts="-h --help list probe match help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__profile__subcmd__help)
            opts="list probe match help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__profile__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__profile__subcmd__help__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__profile__subcmd__help__subcmd__match)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__profile__subcmd__help__subcmd__probe)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__profile__subcmd__list)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__profile__subcmd__match)
            opts="-X -h --exclusive --reader --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__profile__subcmd__probe)
            opts="-X -h --exclusive --reader --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__readers)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__rules)
            opts="-h --help list explain help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__rules__subcmd__explain)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__rules__subcmd__help)
            opts="list explain help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__rules__subcmd__help__subcmd__explain)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__rules__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__rules__subcmd__help__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__rules__subcmd__list)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__saip)
            opts="-h --help parse help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__saip__subcmd__help)
            opts="parse help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__saip__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__saip__subcmd__help__subcmd__parse)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__saip__subcmd__parse)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__scan)
            opts="-X -b -h --exclusive --json --tui --dialect --reader --reader-index --max-depth --max-children --max-nodes --max-directories --sfb --scan-file-break --sffs --score --severity --baseline --fail-on --sarif --csv --tar --tar-filter --class --terminal-profile --sms-deliver-report --sfrv --reserved-file-ids --tar-uncapped --face --theme --color --headless --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --dialect)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reader-index)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-depth)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-children)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-nodes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-directories)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --severity)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sarif)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --csv)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --tar)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --tar-filter)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --class)
                    COMPREPLY=($(compgen -W "etsi gsm" -- "${cur}"))
                    return 0
                    ;;
                --face)
                    COMPREPLY=($(compgen -W "rich plain compact legacy" -- "${cur}"))
                    return 0
                    ;;
                --theme)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --color)
                    COMPREPLY=($(compgen -W "auto always never" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__sms)
            opts="-h --help decode help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__sms__subcmd__decode)
            opts="-h --tpdu --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__sms__subcmd__help)
            opts="decode help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__sms__subcmd__help__subcmd__decode)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__sms__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__trace)
            opts="-h --json --show-raw-apdu --no-suppress-select --no-suppress-status --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ts48)
            opts="-h --help compare help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ts48__subcmd__compare)
            opts="-b -h --json --reader --dialect --max-depth --max-children --max-nodes --max-directories --sfb --scan-file-break --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reader)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dialect)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-depth)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-children)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-nodes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-directories)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ts48__subcmd__help)
            opts="compare help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ts48__subcmd__help__subcmd__compare)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__ts48__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sim__subcmd__doctor__subcmd__why)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
    esac
}

if [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 4 || "${BASH_VERSINFO[0]}" -gt 4 ]]; then
    complete -F _sim__doctor -o nosort -o bashdefault -o default sim-doctor
else
    complete -F _sim__doctor -o bashdefault -o default sim-doctor
fi
