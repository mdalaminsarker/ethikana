<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class PlaceSubType extends Model
{
    //
    protected $table='subType';
    protected $fillable = [
        'type',
        'subType',

    ];


}
