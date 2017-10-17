<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class PlaceSubType extends Model
{
    //
    protected $table='subtype';
    protected $fillable = [
        'type',
        'subType',

    ];


}

