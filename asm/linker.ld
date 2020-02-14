SECTIONS {
    . = %ADDR%;
    .text :
    ALIGN(4) {
        %PATH%(.text);
    }
}
