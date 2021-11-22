;;
;; Reflective Loader
;;
;; GuidePoint Security LLC
;;
;; Threat and Attack Simulation
;;
[BITS 32]

;;
;; Export
;;
GLOBAL _GetIp
GLOBAL _Hooks

[SECTION .text$C]

_Hooks:
	dq 0

[SECTION .text$F]

_GetIp:
	;;
	;; Execute next instruction
	;; 
	call	_get_ret_ptr

_get_ret_ptr:
	;;
	;; Pop address and sub diff
	;;
	pop	eax
	sub	eax, 5
	ret


_Leave:
	db 'E', 'N', 'D', 'O', 'F', 'C', 'O', 'D', 'E'
