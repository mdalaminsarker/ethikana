<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class analytics extends Model
{
    //
    protected $table='analytics';

    protected $fillable = [
        'search_count',
        'code_count',
        'private_count',
        'public_count',
        'saved_count',


    ];
}

