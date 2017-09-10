<?php

return [

    'default' => 'local',

    'cloud' => 's3',

    'disks' => [

        'local' => [
            'driver' => 'local',
            'root' => storage_path('storage'),
        ],

        'public' => [
            'driver' => 'local',
            'root' => storage_path('public'),
            'visibility' => 'public',
        ],
        'json' => [
            'driver' => 'local',
            'root'   => storage_path().'/json',
        ],
        's3' => [
            'driver' => 's3',
            'key' => 'your-key',
            'secret' => 'your-secret',
            'region' => 'your-region',
            'bucket' => 'your-bucket',
        ],
        /*
        'uploads' => [
            'driver' => 'local',
            'root' => public_path('uploads'),
        ],*/

    ],

    'storage' => [
        'driver' => 'local',
        'root'   => storage_path(),
    ],

];