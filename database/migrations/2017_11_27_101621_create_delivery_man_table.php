<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateDeliveryManTable extends Migration
{

    public function up()
    {
        Schema::create('DeliveryMan', function(Blueprint $table) {
            $table->increments('id');
            $table->integer('delivery_man_id')->unsigned()->nullable();
            $table->integer('company_id')->unsigned()->nullable();
            $table->string('last_lon')->nullable();
            $table->string('last_lat')->nullable();
            $table->boolean('active')->default(0);
            $table->boolean('verified')->default(0);
            $table->timestamps();

            // Schema declaration
            // Constraints declaration

        });
    }

    public function down()
    {
        Schema::drop('DeliveryMan');
    }
}
