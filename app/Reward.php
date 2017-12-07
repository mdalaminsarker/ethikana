<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class Reward extends Model
{
    //
    protected $table='rewards';
    protected $fillable = [
        'rewards_name',
	    'required_points',
        'isActive'
    ];

    public function rewardrequest()
    {
        return $this->hasMany('App\RewardRedeemRequest');
    }
}
