<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class OneTimeReward extends Model
{
    //
    protected $table = 'one_time_rewards';

    public function oneTimeRewards()
    {
        return $this->belongsTo('App\User','user_id');
    }
}
