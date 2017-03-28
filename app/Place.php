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
        'city',
        'area',
        'postCode',
        'flag',
        'device_ID',
        'uCode',
        'user_id',
    ];
    public function user()
    {
        return $this->belongsTo(User::class);
    }
}
