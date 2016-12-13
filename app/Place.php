<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class Place extends Model
{
    //
    protected $table='places';
    protected $fillable = [
        'longitude',
        'latitude',
        'Address',
        'flag',
        'device_ID',
        'uCode',
    ];
}
