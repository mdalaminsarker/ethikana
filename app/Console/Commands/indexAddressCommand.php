<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use TeamTNT\TNTSearch\TNTSearch;
use App\Place;
use Exception;
class IndexAddressCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'index:places';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Index the places table';

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     *
     * @return mixed
     */
    public function handle()
    {
      $tnt = new TNTSearch;
       $tnt->loadConfig([
          'driver'    => 'mysql',
          'host'      => 'localhost',
          'database'  => 'ethikana',
          'username'  => 'root',
          'password'  => 'root',
          'storage'   => '/var/www/html/ethikana/storage/custom/'
        ]);
        $indexer = $tnt->createIndex('places.index');
        $indexer->query('SELECT id, Address,area,uCode from places;');
        $indexer->run();
    }
}
