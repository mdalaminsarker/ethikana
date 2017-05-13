<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateReferralLogTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('referrals_log', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('ref_code_referrer')->unsigned();
            $table->integer('ref_code_redeemer')->unsigned();
            $table->foreign('ref_code_referrer')->references('id')->on('users')->onDelete('cascade');
            $table->foreign('ref_code_redeemer')->references('id')->on('users')->onDelete('cascade');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('referrals_log');
    }
}
