<?php

namespace DB
{
    class MySQLi
    {
        private object|null $connection;

        function __construct($connection)
        {
            $this->connection = $connection;
        }
    }
}

namespace {
    class Session
    {
        protected object $adaptor;
        protected string $session_id;
        public $data;

        public function __construct($adaptor, $session_id, $data)
        {
            $this->adaptor = $adaptor;
            $this->session_id = $session_id;
            $this->data = $data;
        }
    }
}

namespace Twig\Cache
{
    class FilesystemCache
    {

    }
}
