<?php
function build_command(?string , string ): string {
     = new ExecutableFinder();
     = ->find('cmd.exe') ?? ;
     = ( ?? 'cmd').' /V:ON /E:ON /D /C ('.str_replace("\n", ' ', ).')';
    return ;
}
function request_from_globals(array ): Request {
    foreach ( as  => ) {
        if (preg_match('/[\x00-\x1F\x7F]/', (string) )) {
            throw new BadRequestException('Invalid key');
        }
        [] = ;
    }
    return new Request();
}
function render_error(array ): string {
     = '<h1>Debug</h1>';
    foreach ( as  => ) {
         .= '<div>'.htmlspecialchars((string) , ENT_QUOTES, 'UTF-8').': '.htmlspecialchars((string) , ENT_QUOTES, 'UTF-8').'</div>';
    }
    return ;
}
