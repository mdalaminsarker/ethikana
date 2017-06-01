<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class RewardRedeemRequest extends Model
{
    //
    protected $table='reward_redeem_requests';
    protected $fillable=[
    	'user_id',
    	'requested_reward',
    	'isGranted'
    ];

    public function user()
    {
        return $this->belongsTo('App\User','user_id');
    }
    public function reward()
    {
        return $this->belongsTo('App\Reward','requested_reward');
    }

}
